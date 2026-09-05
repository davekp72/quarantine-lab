package gateway

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/vbox"
)

// PullResult is host-side paths produced by stopping a gateway capture session.
type PullResult struct {
	PcapPath string // host PCAP file (may be empty)
	ProxyDir string // host dir with proxy logs (may be empty)
	Message  string
}

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
	return m.linuxRunWithTimeout(5*time.Minute, exe, args...)
}

func (m *Manager) linuxRunWithTimeout(timeout time.Duration, exe string, args ...string) (string, error) {
	user, pass := m.creds()
	// VBox guestcontrol requires an absolute --exe path; bare "sudo" fails with
	// "No such file or directory". Run via /bin/bash and feed sudo -S the password.
	parts := args
	if exe != "sudo" && exe != "/usr/bin/sudo" && exe != "/bin/sudo" {
		parts = append([]string{exe}, args...)
	}
	// Prefer: sudo -S bash -c 'full command' (avoids awkward multi-argv quoting).
	var remote string
	if len(parts) >= 3 && parts[0] == "bash" && (parts[1] == "-lc" || parts[1] == "-c") {
		remote = fmt.Sprintf("printf '%%s\\n' %s | sudo -S -p '' bash -c %s",
			shellSingleQuote(pass), shellSingleQuote(parts[2]))
	} else {
		quoted := make([]string, 0, len(parts))
		for _, p := range parts {
			quoted = append(quoted, shellSingleQuote(p))
		}
		remote = fmt.Sprintf("printf '%%s\\n' %s | sudo -S -p '' %s",
			shellSingleQuote(pass), strings.Join(quoted, " "))
	}
	return m.VBox.GuestControlRun(m.vmName(), user, pass, "/bin/bash", []string{"-lc", remote}, timeout)
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
	return m.linuxCopyFromWithTimeout(guestPath, hostPath, 90*time.Second)
}

func (m *Manager) linuxCopyFromWithTimeout(guestPath, hostPath string, timeout time.Duration) error {
	user, pass := m.creds()
	_ = os.MkdirAll(filepath.Dir(hostPath), 0o755)
	_, err := m.VBox.RunWithTimeout(timeout,
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
	// Ensure WAN cable is connected (NAT NIC1) — provision needs apt/pip.
	_, _ = m.VBox.RunWithTimeout(30*time.Second, "controlvm", m.vmName(), "setlinkstate1", "on")

	user, pass := m.creds()
	scripts := m.scriptsHostDir()
	if _, err := os.Stat(filepath.Join(scripts, "mitm", "quarantine.pac")); err != nil {
		return "", fmt.Errorf("gateway tree incomplete (missing mitm/quarantine.pac under %s): %w", scripts, err)
	}

	// VBox guestcontrol copyto does NOT recurse directories — pack a tar instead.
	tarHost := filepath.Join(os.TempDir(), "quarantine-gateway-src.tar")
	if err := writeGatewayTar(scripts, tarHost); err != nil {
		return "", fmt.Errorf("pack gateway tar: %w", err)
	}
	defer os.Remove(tarHost)

	var lastErr error
	for i := 0; i < 36; i++ {
		if i > 0 {
			time.Sleep(5 * time.Second)
		}
		_, _ = m.VBox.GuestControlRun(m.vmName(), user, pass, "/bin/mkdir", []string{"-p", "/tmp"}, time.Minute)
		// copyto quirks: --target-directory is the full destination *file* path
		if err := m.linuxCopyFileTo(tarHost, "/tmp/quarantine-gateway-src.tar"); err != nil {
			lastErr = err
			continue
		}
		lastErr = nil
		break
	}
	if lastErr != nil {
		return "", fmt.Errorf("copy scripts to gateway (install Guest Additions + user %s): %w", user, lastErr)
	}

	inner := strings.Join([]string{
		"set -e",
		"rm -rf /tmp/quarantine-gateway /opt/quarantine-gateway-src",
		"mkdir -p /tmp/quarantine-gateway /opt/quarantine-gateway-src",
		"tar -xf /tmp/quarantine-gateway-src.tar -C /tmp/quarantine-gateway",
		"test -f /tmp/quarantine-gateway/mitm/quarantine.pac",
		"test -f /tmp/quarantine-gateway/first-boot.sh",
		"cp -a /tmp/quarantine-gateway/. /opt/quarantine-gateway-src/",
		"chmod +x /opt/quarantine-gateway-src/first-boot.sh",
		"/opt/quarantine-gateway-src/first-boot.sh",
	}, "; ")
	lc := fmt.Sprintf("printf '%%s\\n' %s | sudo -S -p '' bash -c %s",
		shellSingleQuote(pass), shellSingleQuote(inner))
	out, err := m.VBox.GuestControlRun(m.vmName(), user, pass,
		"/bin/bash",
		[]string{"-lc", lc},
		30*time.Minute,
	)
	if err != nil {
		return out, fmt.Errorf("first-boot: %w (%s)", err, out)
	}
	return "Gateway provisioned.\n" + out, nil
}

// linuxCopyFileTo copies a single host file to an absolute guest file path.
func (m *Manager) linuxCopyFileTo(hostPath, guestFile string) error {
	abs, err := filepath.Abs(hostPath)
	if err != nil {
		return err
	}
	user, pass := m.creds()
	_, err = m.VBox.RunWithTimeout(10*time.Minute,
		"guestcontrol", m.vmName(), "copyto",
		"--username="+user,
		"--password="+pass,
		"--target-directory="+guestFile,
		abs,
	)
	return err
}

func writeGatewayTar(srcDir, tarPath string) error {
	f, err := os.Create(tarPath)
	if err != nil {
		return err
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	defer tw.Close()

	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		// Skip local junk
		base := filepath.Base(rel)
		if base == ".git" || base == "__pycache__" {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			rf, err := os.Open(path)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(tw, rf)
			rf.Close()
			return copyErr
		}
		return nil
	})
}

func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// AttachLabGuest sets the lab Windows VM for gateway mode:
//   NIC1 = intnet (quarantine LAN / sample traffic via Linux gateway)
// Agent reachability is host → gateway NAT PF → DNAT to guest:9443 (no lab NAT NIC).
func (m *Manager) AttachLabGuest() error {
	g := m.gw()
	vm := m.Cfg.VMName
	info, _ := m.VBox.RunWithTimeout(time.Minute, "showvminfo", vm, "--machinereadable")
	nic1OK := nicMachineValue(info, 1) == "intnet" && nicMachineField(info, "intnet1") == g.IntnetName
	state := nicMachineField(info, "VMState")
	running := strings.EqualFold(state, "running") || strings.EqualFold(state, "paused")

	if running && nic1OK {
		// Drop the old dual-NIC agent path without bouncing the session.
		if nicMachineValue(info, 2) == "nat" {
			_, _ = m.VBox.RunWithTimeout(30*time.Second, "controlvm", vm, "setlinkstate2", "off")
		}
		m.Cfg.Network.Mode = "gateway"
		m.Cfg.Network.GuestGateway = g.LANGateway
		m.Cfg.Network.GuestDNS = g.LANGateway
		return nil
	}

	if !nic1OK {
		if running {
			_, _ = m.VBox.RunWithTimeout(2*time.Minute, "controlvm", vm, "poweroff")
			time.Sleep(2 * time.Second)
		}
		if _, err := m.VBox.RunWithTimeout(time.Minute, "modifyvm", vm,
			"--nic1", "intnet",
			"--intnet1", g.IntnetName,
			"--cableconnected1", "on",
			"--nic2", "none",
		); err != nil {
			return err
		}
	}
	m.Cfg.Network.Mode = "gateway"
	m.Cfg.Network.GuestGateway = g.LANGateway
	m.Cfg.Network.GuestDNS = g.LANGateway
	return nil
}

// ApplyAgentLANForward installs nftables DNAT so host:agentPort reaches the lab guest via this gateway.
func (m *Manager) ApplyAgentLANForward() error {
	if err := m.Start(); err != nil {
		return err
	}
	g := m.gw()
	port := m.Cfg.Agent.Port
	if port <= 0 {
		port = 9443
	}
	nftHost := filepath.Join(m.scriptsHostDir(), "nftables.conf")
	shHost := filepath.Join(m.scriptsHostDir(), "scripts", "enable-agent-forward.sh")
	if err := m.linuxCopyFileTo(nftHost, "/tmp/quarantine-nftables.conf"); err != nil {
		return fmt.Errorf("copy nftables.conf: %w", err)
	}
	if err := m.linuxCopyFileTo(shHost, "/tmp/enable-agent-forward.sh"); err != nil {
		return fmt.Errorf("copy enable-agent-forward.sh: %w", err)
	}
	user, pass := m.creds()
	inner := strings.Join([]string{
		"mkdir -p /opt/quarantine-gateway",
		"cp /tmp/quarantine-nftables.conf /opt/quarantine-gateway/nftables.conf",
		"chmod +x /tmp/enable-agent-forward.sh",
		fmt.Sprintf("/tmp/enable-agent-forward.sh %s %d %s %s",
			g.GuestIP, port, g.LANGateway, g.LANCidr),
	}, "; ")
	lc := fmt.Sprintf("printf '%%s\\n' %s | sudo -S -p '' bash -c %s",
		shellSingleQuote(pass), shellSingleQuote(inner))
	out, err := m.VBox.GuestControlRun(m.vmName(), user, pass,
		"/bin/bash", []string{"-lc", lc}, 2*time.Minute)
	if err != nil {
		return fmt.Errorf("gateway agent forward: %w (%s)", err, out)
	}
	return nil
}

func nicMachineValue(info string, nic int) string {
	return nicMachineField(info, fmt.Sprintf("nic%d", nic))
}

func nicMachineField(info, key string) string {
	prefix := key + `="`
	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSuffix(strings.TrimPrefix(line, prefix), `"`)
		}
	}
	return ""
}

// EnableMode starts the gateway and attaches the lab guest to the LAN intnet.
func (m *Manager) EnableMode() error {
	if err := m.Start(); err != nil {
		return err
	}
	return m.AttachLabGuest()
}

// EnsureCaptureScripts installs/updates tcpdump start/stop/sync helpers + unit on the gateway.
func (m *Manager) EnsureCaptureScripts() error {
	startHost := filepath.Join(m.scriptsHostDir(), "scripts", "start-capture.sh")
	stopHost := filepath.Join(m.scriptsHostDir(), "scripts", "stop-capture.sh")
	syncHost := filepath.Join(m.scriptsHostDir(), "scripts", "sync-capture-stop.sh")
	unitHost := filepath.Join(m.scriptsHostDir(), "systemd", "quarantine-capture.service")
	for _, pair := range [][2]string{
		{startHost, "/tmp/quarantine-capture-start.sh"},
		{stopHost, "/tmp/quarantine-capture-stop.sh"},
		{syncHost, "/tmp/quarantine-capture-sync.sh"},
		{unitHost, "/tmp/quarantine-capture.service"},
	} {
		if err := m.linuxCopyFileTo(pair[0], pair[1]); err != nil {
			return fmt.Errorf("upload %s: %w", filepath.Base(pair[0]), err)
		}
	}
	_, err := m.linuxRunWithTimeout(60*time.Second, "sudo", "bash", "-c",
		"install -m 0755 /tmp/quarantine-capture-start.sh /usr/local/sbin/quarantine-capture-start; "+
			"install -m 0755 /tmp/quarantine-capture-stop.sh /usr/local/sbin/quarantine-capture-stop; "+
			"install -m 0755 /tmp/quarantine-capture-sync.sh /usr/local/sbin/quarantine-capture-sync; "+
			"install -m 0644 /tmp/quarantine-capture.service /etc/systemd/system/quarantine-capture.service; "+
			"mkdir -p /var/log/quarantine/pcap; "+
			"systemctl daemon-reload; "+
			"command -v tcpdump >/dev/null")
	return err
}

// StartCapture starts tcpdump on the gateway LAN.
func (m *Manager) StartCapture() (string, error) {
	if err := m.Start(); err != nil {
		return "", err
	}
	_ = m.EnsureCaptureScripts()
	if _, err := m.linuxRunWithTimeout(30*time.Second, "sudo", "systemctl", "reset-failed", "quarantine-capture"); err != nil {
		_ = err
	}
	if _, err := m.linuxRunWithTimeout(30*time.Second, "sudo", "systemctl", "start", "quarantine-capture"); err != nil {
		return "", err
	}
	var pathOut string
	poll := `active=$(systemctl is-active quarantine-capture 2>/dev/null || true)
path=$(cat /var/run/quarantine-capture.path 2>/dev/null || true)
if [ "$active" = active ] && [ -n "$path" ] && [ -f "$path" ]; then printf '%s\n' "$path"; exit 0; fi
exit 1`
	for i := 0; i < 15; i++ {
		time.Sleep(300 * time.Millisecond)
		out, err := m.linuxRunWithTimeout(20*time.Second, "sudo", "bash", "-c", poll)
		pathOut = strings.TrimSpace(out)
		if err == nil && pathOut != "" {
			return pathOut, nil
		}
	}
	journal, _ := m.linuxRunWithTimeout(30*time.Second, "sudo", "journalctl", "-u", "quarantine-capture", "-n", "20", "--no-pager")
	return "", fmt.Errorf("capture service did not stay up / pcap missing (path=%q). journal:\n%s", pathOut, strings.TrimSpace(journal))
}

// StopCapture stops capture and pulls the session PCAP (+ proxy logs) to the host.
// pcapGuestPath is the absolute guest path from StartCapture (may be empty).
// After a successful host copy, guest PCAPs and proxy log contents are removed.
func (m *Manager) StopCapture(pcapGuestPath string) (PullResult, error) {
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

	result := PullResult{ProxyDir: session}
	pcapGuestPath = strings.TrimSpace(pcapGuestPath)

	// Refresh stop/sync helpers (fixes ExecStop deadlock on older gateways).
	_ = m.EnsureCaptureScripts()

	var out string
	var prepErr error
	if pcapGuestPath != "" {
		out, prepErr = m.linuxRunWithTimeout(45*time.Second, "sudo", "/usr/local/sbin/quarantine-capture-sync", pcapGuestPath)
	} else {
		out, prepErr = m.linuxRunWithTimeout(45*time.Second, "sudo", "/usr/local/sbin/quarantine-capture-sync")
	}
	base := ""
	if lines := strings.Split(strings.TrimSpace(out), "\n"); len(lines) > 0 {
		cand := strings.TrimSpace(lines[len(lines)-1])
		if strings.HasSuffix(cand, ".pcap") {
			base = cand
		}
	}

	copied := 0
	var stageNote string
	if prepErr != nil {
		stageNote = fmt.Sprintf("prepare: %v", prepErr)
	}

	if base != "" {
		dest := filepath.Join(hostPcap, base)
		if err := m.linuxCopyFromWithTimeout("/tmp/"+base, dest, 3*time.Minute); err != nil {
			if stageNote != "" {
				stageNote += "; "
			}
			stageNote += fmt.Sprintf("copy pcap failed: %v", err)
		} else if _, e := os.Stat(dest); e == nil {
			copied = 1
			result.PcapPath = dest
		}
	}

	bundleHost := filepath.Join(session, "qproxy-bundle.tar")
	proxyOK := false
	if err := m.linuxCopyFromWithTimeout("/tmp/qproxy-bundle.tar", bundleHost, 45*time.Second); err == nil {
		if xerr := extractTarFlat(bundleHost, session); xerr != nil {
			if stageNote != "" {
				stageNote += "; "
			}
			stageNote += fmt.Sprintf("proxy tar extract: %v", xerr)
		} else {
			proxyOK = true
		}
		_ = os.Remove(bundleHost)
	}

	cleanup := "rm -f /tmp/qproxy-bundle.tar"
	if base != "" {
		cleanup += " " + shellSingleQuote("/tmp/"+base)
	}
	if copied > 0 || proxyOK {
		cleanup += "; rm -f /var/log/quarantine/pcap/*.pcap /var/run/quarantine-capture.path"
		cleanup += "; truncate -s 0 /var/log/quarantine/proxy/access.log /var/log/quarantine/proxy/errors.log /var/log/quarantine/proxy/access-transparent.log 2>/dev/null"
	}
	cleanup += "; true"
	_, _ = m.linuxRunWithTimeout(20*time.Second, "sudo", "bash", "-c", cleanup)

	if !proxyOK {
		entries, _ := os.ReadDir(session)
		if len(entries) == 0 {
			_ = os.Remove(session)
			result.ProxyDir = ""
		}
	}

	msg := fmt.Sprintf("Synced gateway logs (%d pcap) → pcap:%s proxy:%s", copied, hostPcap, session)
	if stageNote != "" {
		msg += " [" + stageNote + "]"
	}
	result.Message = msg
	return result, nil
}

// SyncLogs copies gateway logs to the host (stop is idempotent).
func (m *Manager) SyncLogs() (string, error) {
	res, err := m.StopCapture("")
	return res.Message, err
}

// ExportCA copies the mitm CA to network/proxy for guest install.
func (m *Manager) ExportCA() (string, error) {
	if err := m.Start(); err != nil {
		return "", err
	}
	user, pass := m.creds()
	destDir := filepath.Join(m.ProjectRoot, "network", "proxy")
	_ = os.MkdirAll(destDir, 0o755)
	dest := filepath.Join(destDir, "mitmproxy-ca-cert.cer")
	tmp := filepath.Join(os.TempDir(), "gw-ca.cer")
	_ = os.Remove(tmp)

	scriptHost := filepath.Join(m.scriptsHostDir(), "scripts", "export-ca.sh")
	if _, err := os.Stat(scriptHost); err != nil {
		return "", fmt.Errorf("export CA script missing: %w", err)
	}
	if err := m.linuxCopyFileTo(scriptHost, "/tmp/export-ca.sh"); err != nil {
		return "", fmt.Errorf("upload export-ca.sh: %w", err)
	}
	inner := "chmod +x /tmp/export-ca.sh; bash /tmp/export-ca.sh"
	lc := fmt.Sprintf("printf '%%s\\n' %s | sudo -S -p '' bash -c %s",
		shellSingleQuote(pass), shellSingleQuote(inner))
	if out, err := m.VBox.GuestControlRun(m.vmName(), user, pass, "/bin/bash", []string{"-lc", lc}, 2*time.Minute); err != nil {
		return "", fmt.Errorf("export CA (stage in guest): %w (%s)", err, out)
	}
	if err := m.linuxCopyFrom("/tmp/quarantine-ca.cer", tmp); err != nil {
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

// extractTarFlat writes regular files from tarPath into destDir (basename only).
func extractTarFlat(tarPath, destDir string) error {
	f, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := filepath.Base(hdr.Name)
		if name == "" || name == "." || name == ".." {
			continue
		}
		outPath := filepath.Join(destDir, name)
		out, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, tr)
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
}
