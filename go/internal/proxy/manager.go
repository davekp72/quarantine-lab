package proxy

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quarantine-lab/quarantine/internal/config"
)

// Manager runs mitmproxy as a detached host process with a persisted PID state file.
type Manager struct {
	Cfg  *config.Config
	Root string
	mu   sync.Mutex
}

type networkState struct {
	MitmproxyPID int    `json:"mitmproxyPid,omitempty"`
	PacPID       int    `json:"pacPid,omitempty"`
	SessionDir   string `json:"sessionDir,omitempty"`
	StartedAt    string `json:"startedAt,omitempty"`
	ListenPort   int    `json:"listenPort,omitempty"`
	PacPort      int    `json:"pacPort,omitempty"`
}

// New creates proxy manager.
func New(cfg *config.Config, projectRoot string) *Manager {
	return &Manager{Cfg: cfg, Root: projectRoot}
}

func (m *Manager) logDir() string {
	dir := strings.TrimSpace(m.Cfg.Network.Proxy.LogDir)
	if dir == "" {
		dir = filepath.Join(m.Cfg.DataDir(), "logs", "proxy")
	}
	return dir
}

func (m *Manager) statePath() string {
	return filepath.Join(m.logDir(), "quarantine-network.state.json")
}

func (m *Manager) listenPort() int {
	if m.Cfg.Network.Proxy.ListenPort > 0 {
		return m.Cfg.Network.Proxy.ListenPort
	}
	return 8080
}

func (m *Manager) pacPort() int {
	if m.Cfg.Network.Proxy.PACPort > 0 {
		return m.Cfg.Network.Proxy.PACPort
	}
	return 8081
}

func (m *Manager) listenHost() string {
	h := strings.TrimSpace(m.Cfg.Network.Proxy.ListenHost)
	if h == "" {
		return "0.0.0.0"
	}
	return h
}

func (m *Manager) mitmdumpPath() (string, error) {
	venv := filepath.Join(m.Root, ".venv", "Scripts", "mitmdump.exe")
	if _, err := os.Stat(venv); err == nil {
		return venv, nil
	}
	p, err := exec.LookPath("mitmdump")
	if err != nil {
		return "", fmt.Errorf("mitmdump not found; run Setup-Dependencies.ps1")
	}
	return p, nil
}

func (m *Manager) readState() networkState {
	raw, err := os.ReadFile(m.statePath())
	if err != nil {
		return networkState{}
	}
	var st networkState
	_ = json.Unmarshal(raw, &st)
	return st
}

func (m *Manager) writeState(st networkState) error {
	if err := os.MkdirAll(m.logDir(), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.statePath(), raw, 0o644)
}

func (m *Manager) clearState() {
	_ = os.Remove(m.statePath())
}

func processName(pid int) string {
	if pid <= 0 {
		return ""
	}
	out, err := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/FO", "CSV", "/NH").Output()
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(out))
	if line == "" || strings.HasPrefix(strings.ToLower(line), "info:") {
		return ""
	}
	// "python.exe","1234",...
	parts := strings.Split(line, ",")
	if len(parts) == 0 {
		return ""
	}
	return strings.Trim(parts[0], `"`)
}

func pidsListeningOnPort(port int) []int {
	out, err := exec.Command("netstat", "-ano", "-p", "tcp").Output()
	if err != nil {
		return nil
	}
	want := ":" + strconv.Itoa(port)
	seen := map[int]struct{}{}
	var pids []int
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		if !strings.EqualFold(fields[3], "LISTENING") {
			continue
		}
		if !strings.HasSuffix(fields[1], want) {
			continue
		}
		pid, err := strconv.Atoi(fields[4])
		if err != nil || pid <= 0 {
			continue
		}
		if _, ok := seen[pid]; ok {
			continue
		}
		seen[pid] = struct{}{}
		pids = append(pids, pid)
	}
	return pids
}

func killListenersOnPort(port int) error {
	allowed := map[string]bool{
		"mitmdump.exe": true,
		"python.exe":   true,
		"python3.exe":  true,
	}
	for _, pid := range pidsListeningOnPort(port) {
		name := strings.ToLower(processName(pid))
		if name == "" {
			continue
		}
		if !allowed[name] {
			return fmt.Errorf("port %d is in use by %s (PID %d); stop it or change network.proxy.listenPort", port, name, pid)
		}
		killPID(pid)
	}
	return nil
}

func portOpen(host string, port int) bool {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if host == "0.0.0.0" || host == "::" {
		addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	}
	c, err := net.DialTimeout("tcp", addr, 400*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func findPython() string {
	if p, err := exec.LookPath("python"); err == nil {
		return p
	}
	candidates := []string{
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", "Python", "Python313", "python.exe"),
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", "Python", "Python312", "python.exe"),
		`C:\Python313\python.exe`,
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

func publishCA(logDir, pacDir string) string {
	candidates := []string{
		filepath.Join(logDir, "certs", "mitmproxy-ca-cert.cer"),
		filepath.Join(os.Getenv("USERPROFILE"), ".mitmproxy", "mitmproxy-ca-cert.cer"),
		filepath.Join(os.Getenv("USERPROFILE"), ".mitmproxy", "mitmproxy-ca-cert.pem"),
	}
	var src string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			src = c
			break
		}
	}
	if src == "" {
		return ""
	}
	_ = os.MkdirAll(pacDir, 0o755)
	_ = os.MkdirAll(filepath.Join(logDir, "certs"), 0o755)
	dest := filepath.Join(pacDir, "mitmproxy-ca-cert.cer")
	raw, err := os.ReadFile(src)
	if err != nil {
		return ""
	}
	_ = os.WriteFile(dest, raw, 0o644)
	_ = os.WriteFile(filepath.Join(logDir, "certs", "mitmproxy-ca-cert.cer"), raw, 0o644)
	return dest
}

// Start launches mitmdump (detached) with block script and session logs.
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.Cfg.Network.Proxy.Enabled {
		return fmt.Errorf("proxy disabled in config")
	}

	st := m.readState()
	if processAlive(st.MitmproxyPID) {
		fmt.Printf("Quarantine proxy already running (PID %d on port %d)\n", st.MitmproxyPID, m.listenPort())
		return nil
	}

	killPID(st.MitmproxyPID)
	killPID(st.PacPID)
	if err := killListenersOnPort(m.listenPort()); err != nil {
		return err
	}
	_ = killListenersOnPort(m.pacPort())

	bin, err := m.mitmdumpPath()
	if err != nil {
		return err
	}

	logDir := m.logDir()
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return err
	}
	session := time.Now().Format("20060102-150405")
	sessionDir := filepath.Join(logDir, session)
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		return err
	}

	script := filepath.Join(m.Root, "network", "proxy", "block_private.py")
	pacPath := filepath.Join(m.Root, "network", "proxy", "quarantine.pac")
	pacDir := filepath.Dir(pacPath)
	caPath := publishCA(logDir, pacDir)

	flowsPath := filepath.Join(sessionDir, "flows.mitm")
	accessLog := filepath.Join(sessionDir, "access.log")
	errorLog := filepath.Join(sessionDir, "errors.log")
	startupLog := filepath.Join(sessionDir, "startup.log")

	args := []string{
		"--listen-host", m.listenHost(),
		"--listen-port", strconv.Itoa(m.listenPort()),
		"--set", "block_global=false",
		"-w", flowsPath,
	}
	if _, err := os.Stat(script); err == nil {
		args = append(args, "-s", script)
	}

	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(),
		"QUARANTINE_ACCESS_LOG="+accessLog,
		"QUARANTINE_ERROR_LOG="+errorLog,
		"QUARANTINE_PAC_PATH="+pacPath,
	)
	if caPath != "" {
		cmd.Env = append(cmd.Env, "QUARANTINE_CA_PATH="+caPath)
	}
	startupFile, err := os.Create(startupLog)
	if err != nil {
		return err
	}
	cmd.Stdout = startupFile
	cmd.Stderr = startupFile
	hideWindow(cmd)
	if err := cmd.Start(); err != nil {
		startupFile.Close()
		return err
	}
	pid := cmd.Process.Pid
	// Detach: release handle so parent exit does not wait; process keeps running.
	_ = cmd.Process.Release()
	startupFile.Close()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			detail, _ := os.ReadFile(startupLog)
			msg := strings.TrimSpace(string(detail))
			if msg != "" {
				return fmt.Errorf("mitmdump exited immediately: %s", msg)
			}
			return fmt.Errorf("mitmdump exited immediately; see %s", startupLog)
		}
		if portOpen(m.listenHost(), m.listenPort()) {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if !processAlive(pid) {
		return fmt.Errorf("mitmdump failed to stay up; see %s", startupLog)
	}

	if caPath == "" {
		caPath = publishCA(logDir, pacDir)
	}

	pacPID := 0
	if py := findPython(); py != "" {
		pacCmd := exec.Command(py, "-m", "http.server", strconv.Itoa(m.pacPort()), "--bind", "0.0.0.0", "--directory", pacDir)
		hideWindow(pacCmd)
		if err := pacCmd.Start(); err == nil {
			pacPID = pacCmd.Process.Pid
			_ = pacCmd.Process.Release()
		}
	}

	st = networkState{
		MitmproxyPID: pid,
		PacPID:       pacPID,
		SessionDir:   sessionDir,
		StartedAt:    time.Now().Format(time.RFC3339),
		ListenPort:   m.listenPort(),
		PacPort:      m.pacPort(),
	}
	if err := m.writeState(st); err != nil {
		return err
	}

	fmt.Printf("Quarantine proxy started.\n")
	fmt.Printf("  mitmdump PID: %d on %s:%d\n", pid, m.listenHost(), m.listenPort())
	if pacPID > 0 {
		fmt.Printf("  PAC server PID: %d on port %d\n", pacPID, m.pacPort())
	}
	fmt.Printf("  Logs: %s\n", sessionDir)
	return nil
}

// Stop stops mitmdump and PAC server.
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	st := m.readState()
	killPID(st.MitmproxyPID)
	killPID(st.PacPID)
	_ = killListenersOnPort(m.listenPort())
	_ = killListenersOnPort(m.pacPort())
	m.clearState()
	fmt.Println("Quarantine proxy stopped.")
	return nil
}

// Status returns running state, including PID when known.
func (m *Manager) Status() string {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.Cfg.IsGatewayMode() {
		return "gateway (mitm on Linux gateway VM — use gateway status)"
	}

	st := m.readState()
	if processAlive(st.MitmproxyPID) {
		return fmt.Sprintf("running (pid %d, port %d)", st.MitmproxyPID, m.listenPort())
	}
	// Orphan listener (started without state, or state lost).
	for _, pid := range pidsListeningOnPort(m.listenPort()) {
		name := strings.ToLower(processName(pid))
		if name == "mitmdump.exe" || name == "python.exe" || name == "python3.exe" {
			return fmt.Sprintf("running (orphaned pid %d on port %d — run proxy stop then start)", pid, m.listenPort())
		}
	}
	return "stopped"
}

// ExportCA publishes the mitm CA into network/proxy for guest install.
// When gatewayExporter is set and network mode is gateway, prefer the gateway CA.
func (m *Manager) ExportCA(gatewayExporter func() (string, error)) (string, error) {
	if m.Cfg.IsGatewayMode() && gatewayExporter != nil {
		path, err := gatewayExporter()
		if err == nil {
			fmt.Printf("Exported gateway mitm CA → %s\n", path)
			return path, nil
		}
		fmt.Printf("Gateway CA export failed (%v); falling back to host mitmproxy CA\n", err)
	}

	candidates := []string{
		filepath.Join(os.Getenv("USERPROFILE"), ".mitmproxy", "mitmproxy-ca-cert.cer"),
		filepath.Join(os.Getenv("USERPROFILE"), ".mitmproxy", "mitmproxy-ca-cert.pem"),
		filepath.Join(m.logDir(), "certs", "mitmproxy-ca-cert.cer"),
		filepath.Join(m.Root, "network", "proxy", "mitmproxy-ca-cert.cer"),
	}
	var src string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			src = c
			break
		}
	}
	if src == "" {
		return "", fmt.Errorf("mitmproxy CA not found; start host proxy or gateway provision first")
	}
	destDir := filepath.Join(m.Root, "network", "proxy")
	_ = os.MkdirAll(destDir, 0o755)
	dest := filepath.Join(destDir, "mitmproxy-ca-cert.cer")
	raw, err := os.ReadFile(src)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(dest, raw, 0o644); err != nil {
		return "", err
	}
	certs := filepath.Join(m.logDir(), "certs")
	_ = os.MkdirAll(certs, 0o755)
	_ = os.WriteFile(filepath.Join(certs, "mitmproxy-ca-cert.cer"), raw, 0o644)
	fmt.Printf("Exported mitm CA → %s\n", dest)
	return dest, nil
}

// Start skips host mitmdump when using the Linux gateway (proxy runs there).
func (m *Manager) StartIfHostMode() error {
	if m.Cfg.IsGatewayMode() {
		fmt.Println("Network mode is gateway — skipping host mitmproxy (proxy runs on gateway VM).")
		return nil
	}
	return m.Start()
}
