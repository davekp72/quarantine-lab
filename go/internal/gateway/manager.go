package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/vbox"
)

// Manager orchestrates the Linux Quarantine-Gateway VirtualBox VM.
type Manager struct {
	Cfg         *config.Config
	VBox        *vbox.Client
	ProjectRoot string
}

func New(cfg *config.Config, vb *vbox.Client, projectRoot string) *Manager {
	return &Manager{Cfg: cfg, VBox: vb, ProjectRoot: projectRoot}
}

func (m *Manager) gw() config.GatewayConfig {
	return m.Cfg.Network.Gateway.WithDefaults(m.Cfg.Network.IntnetName)
}

func (m *Manager) vmName() string {
	return m.gw().VMName
}

func (m *Manager) gatewayFolder() string {
	return filepath.Join(m.Cfg.DataDir(), "gateway")
}

func (m *Manager) scriptsHostDir() string {
	return filepath.Join(m.ProjectRoot, "gateway")
}

// Create registers the gateway VM with NAT + intnet NICs and a disk.
func (m *Manager) Create() (string, error) {
	g := m.gw()
	name := g.VMName
	folder := m.gatewayFolder()
	if err := os.MkdirAll(folder, 0o755); err != nil {
		return "", err
	}

	if _, err := m.VBox.VMState(name); err == nil {
		return name, fmt.Errorf("gateway VM %q already exists", name)
	}

	if _, err := m.VBox.RunWithTimeout(2*time.Minute, "createvm",
		"--name", name,
		"--ostype", "Ubuntu_64",
		"--register",
		"--basefolder", folder,
	); err != nil {
		return "", fmt.Errorf("createvm: %w", err)
	}

	mem := g.MemoryMB
	cpus := g.CPUCount
	diskMB := g.DiskSizeGB * 1024

	mods := [][]string{
		{"--memory", fmt.Sprintf("%d", mem), "--cpus", fmt.Sprintf("%d", cpus)},
		{"--nic1", "nat", "--cableconnected1", "on"},
		{"--nic2", "intnet", "--intnet2", g.IntnetName, "--cableconnected2", "on"},
		{"--audio-driver", "none", "--usb", "off"},
	}
	for _, args := range mods {
		full := append([]string{"modifyvm", name}, args...)
		if _, err := m.VBox.RunWithTimeout(time.Minute, full...); err != nil {
			// audio-driver may differ by VBox version
			if strings.Contains(err.Error(), "audio") {
				continue
			}
			return "", fmt.Errorf("modifyvm %v: %w", args, err)
		}
	}

	sshPort := g.SSHHostPort
	_ = m.VBox.NatPFDelete(name, "gateway-ssh")
	if err := m.VBox.NatPFAdd(name, fmt.Sprintf("gateway-ssh,tcp,,%d,,22", sshPort)); err != nil {
		return "", fmt.Errorf("ssh natpf: %w", err)
	}

	diskPath := filepath.Join(folder, name, name+".vdi")
	_ = os.MkdirAll(filepath.Dir(diskPath), 0o755)
	if _, err := m.VBox.RunWithTimeout(5*time.Minute, "createmedium", "disk",
		"--filename", diskPath,
		"--size", fmt.Sprintf("%d", diskMB),
		"--format", "VDI",
	); err != nil {
		return "", fmt.Errorf("createmedium: %w", err)
	}
	if _, err := m.VBox.RunWithTimeout(time.Minute, "storagectl", name,
		"--name", "SATA", "--add", "sata", "--controller", "IntelAhci",
	); err != nil {
		return "", fmt.Errorf("storagectl: %w", err)
	}
	if _, err := m.VBox.RunWithTimeout(time.Minute, "storageattach", name,
		"--storagectl", "SATA", "--port", "0", "--device", "0",
		"--type", "hdd", "--medium", diskPath,
	); err != nil {
		return "", fmt.Errorf("storageattach disk: %w", err)
	}

	scripts := m.scriptsHostDir()
	if _, err := os.Stat(scripts); err == nil {
		_ = m.VBox.SharedFolderRemove(name, "quarantine-gateway")
		_ = m.VBox.SharedFolderAdd(name, "quarantine-gateway", scripts, true)
	}

	msg := fmt.Sprintf(`Gateway VM %q created.
  Folder: %s
  NIC1: NAT (uplink)  NIC2: intnet %s (LAN %s/24)
  SSH: localhost:%d → guest:22 (user %s)

Next:
  1. Attach Ubuntu Server ISO to SATA port 1 and install (enable OpenSSH + Guest Additions)
  2. quarantine gateway provision
  3. quarantine network gateway
`, name, folder, g.IntnetName, g.LANGateway, sshPort, g.Username)
	return msg, nil
}

// Start boots the gateway VM (headless).
func (m *Manager) Start() error {
	name := m.vmName()
	state, err := m.VBox.VMState(name)
	if err != nil {
		return fmt.Errorf("gateway VM %q missing — run gateway create first: %w", name, err)
	}
	if strings.EqualFold(state, "running") {
		return nil
	}
	_, err = m.VBox.RunWithTimeout(5*time.Minute, "startvm", name, "--type", "headless")
	return err
}

// Stop poweroffs the gateway VM.
func (m *Manager) Stop() error {
	name := m.vmName()
	state, err := m.VBox.VMState(name)
	if err != nil {
		return err
	}
	if !strings.EqualFold(state, "running") {
		return nil
	}
	_, err = m.VBox.RunWithTimeout(2*time.Minute, "controlvm", name, "poweroff")
	return err
}

// Status returns a short status string.
func (m *Manager) Status() string {
	name := m.vmName()
	state, err := m.VBox.VMState(name)
	if err != nil {
		return fmt.Sprintf("missing (%v)", err)
	}
	g := m.gw()
	line := fmt.Sprintf("%s state=%s lan=%s intnet=%s", name, state, g.LANGateway, g.IntnetName)
	if strings.EqualFold(state, "running") {
		if out, err := m.linuxRun("sudo", "/usr/local/sbin/quarantine-gateway-status"); err == nil {
			line += "\n" + strings.TrimSpace(out)
		}
	}
	return line
}

func (m *Manager) creds() (user, pass string) {
	g := m.gw()
	return g.Username, g.Password
}

func (m *Manager) linuxRun(exe string, args ...string) (string, error) {
	user, pass := m.creds()
	return m.VBox.GuestControlRun(m.vmName(), user, pass, exe, args, 5*time.Minute)
}

// linuxCopyTo copies a host path into the Linux guest (forward-slash destinations).
func (m *Manager) linuxCopyTo(hostPath, guestDest string) error {
	user, pass := m.creds()
	_, err := m.VBox.RunWithTimeout(10*time.Minute,
		"guestcontrol", m.vmName(), "copyto",
		"--username="+user,
		"--password="+pass,
		"--target-directory="+guestDest,
		hostPath,
	)
	return err
}

func (m *Manager) linuxCopyFrom(guestPath, hostPath string) error {
	user, pass := m.creds()
	_ = os.MkdirAll(filepath.Dir(hostPath), 0o755)
	_, err := m.VBox.RunWithTimeout(10*time.Minute,
		"guestcontrol", m.vmName(), "copyfrom",
		"--username="+user,
		"--password="+pass,
		"--target-directory="+hostPath,
		guestPath,
	)
	return err
}

// Provision copies gateway scripts into the Linux VM and runs first-boot.sh.
func (m *Manager) Provision() (string, error) {
	if err := m.Start(); err != nil {
		return "", err
	}
	user, pass := m.creds()
	scripts := m.scriptsHostDir()
	var lastErr error
	for i := 0; i < 36; i++ {
		time.Sleep(5 * time.Second)
		_, _ = m.VBox.GuestControlRun(m.vmName(), user, pass, "/bin/mkdir", []string{"-p", "/tmp/quarantine-gateway"}, time.Minute)
		if err := m.linuxCopyTo(scripts, "/tmp/quarantine-gateway"); err != nil {
			lastErr = err
			continue
		}
		lastErr = nil
		break
	}
	if lastErr != nil {
		return "", fmt.Errorf("copy scripts to gateway (install Guest Additions + user %s): %w", user, lastErr)
	}
	out, err := m.VBox.GuestControlRun(m.vmName(), user, pass,
		"/bin/bash",
		[]string{"-lc", "sudo cp -a /tmp/quarantine-gateway/. /opt/quarantine-gateway-src/ 2>/dev/null || sudo cp -a /tmp/quarantine-gateway /opt/quarantine-gateway-src; sudo chmod +x /opt/quarantine-gateway-src/first-boot.sh; sudo /opt/quarantine-gateway-src/first-boot.sh"},
		30*time.Minute,
	)
	if err != nil {
		return out, fmt.Errorf("first-boot: %w (%s)", err, out)
	}
	return "Gateway provisioned.\n" + out, nil
}

// AttachLabGuest sets the lab Windows VM NIC to intnet for gateway mode.
func (m *Manager) AttachLabGuest() error {
	g := m.gw()
	vm := m.Cfg.VMName
	state, _ := m.VBox.VMState(vm)
	running := strings.EqualFold(state, "running") || strings.EqualFold(state, "paused")
	if running {
		_, _ = m.VBox.RunWithTimeout(2*time.Minute, "controlvm", vm, "poweroff")
		time.Sleep(2 * time.Second)
	}
	if _, err := m.VBox.RunWithTimeout(time.Minute, "modifyvm", vm,
		"--nic1", "intnet",
		"--intnet1", g.IntnetName,
		"--cableconnected1", "on",
	); err != nil {
		return err
	}
	m.Cfg.Network.Mode = "gateway"
	m.Cfg.Network.GuestGateway = g.LANGateway
	m.Cfg.Network.GuestDNS = g.LANGateway
	return nil
}

// EnableMode starts the gateway and attaches the lab guest to the LAN intnet.
func (m *Manager) EnableMode() error {
	if err := m.Start(); err != nil {
		return err
	}
	return m.AttachLabGuest()
}

// StartCapture starts tcpdump on the gateway LAN.
func (m *Manager) StartCapture() (string, error) {
	if err := m.Start(); err != nil {
		return "", err
	}
	if _, err := m.linuxRun("sudo", "systemctl", "start", "quarantine-capture"); err != nil {
		return "", err
	}
	pathOut, _ := m.linuxRun("sudo", "cat", "/var/run/quarantine-capture.path")
	return strings.TrimSpace(pathOut), nil
}

// StopCapture stops capture and pulls PCAPs + proxy logs to the host.
func (m *Manager) StopCapture() (string, error) {
	_, _ = m.linuxRun("sudo", "/usr/local/sbin/quarantine-capture-stop")
	_, _ = m.linuxRun("sudo", "systemctl", "stop", "quarantine-capture")
	return m.SyncLogs()
}

// SyncLogs copies gateway /var/log/quarantine to host log dirs.
func (m *Manager) SyncLogs() (string, error) {
	hostPcap := m.Cfg.Network.Capture.LogDir
	if hostPcap == "" {
		hostPcap = filepath.Join(m.Cfg.DataDir(), "logs", "pcap")
	}
	hostProxy := m.Cfg.Network.Proxy.LogDir
	if hostProxy == "" {
		hostProxy = filepath.Join(m.Cfg.DataDir(), "logs", "proxy")
	}
	session := filepath.Join(hostProxy, "gateway-"+time.Now().Format("20060102-150405"))
	_ = os.MkdirAll(hostPcap, 0o755)
	_ = os.MkdirAll(session, 0o755)

	for _, name := range []string{"access.log", "errors.log", "access-transparent.log", "flows.mitm", "flows-transparent.mitm"} {
		_ = m.linuxCopyFrom("/var/log/quarantine/proxy/"+name, filepath.Join(session, name))
	}
	listOut, _ := m.linuxRun("sudo", "bash", "-lc", "ls -1 /var/log/quarantine/pcap/*.pcap 2>/dev/null | tail -5")
	for _, line := range strings.Split(listOut, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		_ = m.linuxCopyFrom(line, filepath.Join(hostPcap, filepath.Base(line)))
	}
	return fmt.Sprintf("Synced gateway logs → pcap:%s proxy:%s", hostPcap, session), nil
}

// ExportCA copies the mitm CA to network/proxy for guest install.
func (m *Manager) ExportCA() (string, error) {
	destDir := filepath.Join(m.ProjectRoot, "network", "proxy")
	_ = os.MkdirAll(destDir, 0o755)
	dest := filepath.Join(destDir, "mitmproxy-ca-cert.cer")
	tmp := filepath.Join(os.TempDir(), "gw-ca.cer")
	_ = os.Remove(tmp)
	err := m.linuxCopyFrom("/etc/quarantine-gateway/mitmproxy-ca-cert.cer", tmp)
	if err != nil {
		err = m.linuxCopyFrom("/root/.mitmproxy/mitmproxy-ca-cert.pem", tmp)
	}
	if err != nil {
		return "", fmt.Errorf("export CA: %w", err)
	}
	if err := copyFile(tmp, dest); err != nil {
		return "", err
	}
	certs := filepath.Join(m.Cfg.DataDir(), "logs", "proxy", "certs")
	_ = os.MkdirAll(certs, 0o755)
	_ = copyFile(tmp, filepath.Join(certs, "mitmproxy-ca-cert.cer"))
	return dest, nil
}

func copyFile(src, dst string) error {
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, raw, 0o644)
}
