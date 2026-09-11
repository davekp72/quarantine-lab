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
	CfgPath     string
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
	// Bind to loopback only — empty host IP exposes SSH on all host interfaces.
	if err := m.VBox.NatPFAdd(name, fmt.Sprintf("gateway-ssh,tcp,127.0.0.1,%d,,22", sshPort)); err != nil {
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
  SSH: localhost:%d → guest:22 (user %s, key-only)
  Key: %s

Next:
  1. Attach Ubuntu Server ISO to SATA port 1 and install (enable OpenSSH + Guest Additions)
  2. quarantine gateway provision   # installs SSH key, disables password SSH, drops NOPASSWD sudo
  3. quarantine network gateway
`, name, folder, g.IntnetName, g.LANGateway, sshPort, g.Username, g.SSHPrivateKey)
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
	line := fmt.Sprintf("%s state=%s lan=%s intnet=%s traffic-mode=%s", name, state, g.LANGateway, g.IntnetName, g.TrafficMode)
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
	// "No such file or directory". Run via /bin/bash and feed sudo -S from a
	// staged guest password file (never embed the password in argv / logs).
	parts := args
	if exe != "sudo" && exe != "/usr/bin/sudo" && exe != "/bin/sudo" {
		parts = append([]string{exe}, args...)
	}
	guestPw, cleanup, err := m.stageSudoPasswordFile()
	if err != nil {
		return "", err
	}
	defer cleanup()

	var remote string
	if len(parts) >= 3 && parts[0] == "bash" && (parts[1] == "-lc" || parts[1] == "-c") {
		remote = fmt.Sprintf("sudo -S -p '' bash -c %s < %s",
			shellSingleQuote(parts[2]), shellSingleQuote(guestPw))
	} else {
		quoted := make([]string, 0, len(parts))
		for _, p := range parts {
			quoted = append(quoted, shellSingleQuote(p))
		}
		remote = fmt.Sprintf("sudo -S -p '' %s < %s",
			strings.Join(quoted, " "), shellSingleQuote(guestPw))
	}
	return m.VBox.GuestControlRun(m.vmName(), user, pass, "/bin/bash", []string{"-lc", remote}, timeout)
}

// stageSudoPasswordFile copies the gateway password to a unique guest temp file
// and returns a cleanup that removes it. Avoids embedding secrets in command lines.
func (m *Manager) stageSudoPasswordFile() (guestPath string, cleanup func(), err error) {
	_, pass := m.creds()
	hostFile, err := os.CreateTemp("", "qlab-sudo-pw-*.tmp")
	if err != nil {
		return "", func() {}, err
	}
	hostPath := hostFile.Name()
	hostCleanup := func() { _ = os.Remove(hostPath) }
	if _, err := hostFile.WriteString(pass + "\n"); err != nil {
		_ = hostFile.Close()
		hostCleanup()
		return "", func() {}, err
	}
	_ = hostFile.Close()
	_ = os.Chmod(hostPath, 0o600)

	guestPath = fmt.Sprintf("/tmp/.qlab-sudo-pw-%d", time.Now().UnixNano())
	if err := m.linuxCopyFileTo(hostPath, guestPath); err != nil {
		hostCleanup()
		return "", func() {}, fmt.Errorf("stage sudo password: %w", err)
	}
	hostCleanup()

	user, pass := m.creds()
	cleanup = func() {
		_, _ = m.VBox.GuestControlRun(m.vmName(), user, pass, "/bin/rm", []string{"-f", guestPath}, 30*time.Second)
	}
	return guestPath, cleanup, nil
}

func (m *Manager) sudoBashLC(inner string, timeout time.Duration) (string, error) {
	user, pass := m.creds()
	guestPw, cleanup, err := m.stageSudoPasswordFile()
	if err != nil {
		return "", err
	}
	defer cleanup()
	lc := fmt.Sprintf("sudo -S -p '' bash -c %s < %s",
		shellSingleQuote(inner), shellSingleQuote(guestPw))
	return m.VBox.GuestControlRun(m.vmName(), user, pass, "/bin/bash", []string{"-lc", lc}, timeout)
}

// linuxCopyTo copies a host path into the Linux guest (forward-slash destinations).
func (m *Manager) linuxCopyTo(hostPath, guestDest string) error {
	user, pass := m.creds()
	auth, cleanup, err := vbox.AuthFlags(user, pass)
	if err != nil {
		return err
	}
	defer cleanup()
	args := []string{"guestcontrol", m.vmName(), "copyto"}
	args = append(args, auth...)
	args = append(args, "--target-directory="+guestDest, hostPath)
	_, err = m.VBox.RunWithTimeout(10*time.Minute, args...)
	return err
}

func (m *Manager) linuxCopyFrom(guestPath, hostPath string) error {
	return m.linuxCopyFromWithTimeout(guestPath, hostPath, 90*time.Second)
}

func (m *Manager) linuxCopyFromWithTimeout(guestPath, hostPath string, timeout time.Duration) error {
	user, pass := m.creds()
	_ = os.MkdirAll(filepath.Dir(hostPath), 0o755)
	auth, cleanup, err := vbox.AuthFlags(user, pass)
	if err != nil {
		return err
	}
	defer cleanup()
	args := []string{"guestcontrol", m.vmName(), "copyfrom"}
	args = append(args, auth...)
	args = append(args, "--target-directory="+hostPath, guestPath)
	_, err = m.VBox.RunWithTimeout(timeout, args...)
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
	out, err := m.sudoBashLC(inner, 30*time.Minute)
	if err != nil {
		return out, fmt.Errorf("first-boot: %w (%s)", err, out)
	}
	if sshOut, sshErr := m.HardenSSH(); sshErr != nil {
		return out, fmt.Errorf("provision ok but SSH harden failed: %w\n%s", sshErr, sshOut)
	} else if sshOut != "" {
		out += "\n" + sshOut
	}
	return "Gateway provisioned.\n" + out, nil
}

// HardenSSH installs the host key, disables password SSH, and drops NOPASSWD:ALL sudo.
func (m *Manager) HardenSSH() (string, error) {
	g := m.gw()
	pub := strings.TrimSpace(g.SSHPublicKey)
	if pub == "" && m.Cfg != nil {
		pub = filepath.Join(m.Cfg.SecretsDir(), "gateway-id_ed25519.pub")
	}
	if _, err := os.Stat(pub); err != nil {
		return "", fmt.Errorf("gateway SSH public key missing (%s) — run setup secrets: %w", pub, err)
	}
	if err := m.linuxCopyFileTo(pub, "/tmp/quarantine-gateway.pub"); err != nil {
		return "", fmt.Errorf("upload gateway SSH public key: %w", err)
	}
	script := filepath.Join(m.scriptsHostDir(), "scripts", "harden-ssh.sh")
	if _, err := os.Stat(script); err != nil {
		return "", fmt.Errorf("missing harden-ssh.sh: %w", err)
	}
	if err := m.linuxCopyFileTo(script, "/tmp/quarantine-harden-ssh.sh"); err != nil {
		return "", fmt.Errorf("upload harden-ssh.sh: %w", err)
	}
	user := g.Username
	inner := strings.Join([]string{
		"set -e",
		"install -m 0755 /tmp/quarantine-harden-ssh.sh /usr/local/sbin/quarantine-harden-ssh",
		"QUARANTINE_USER=" + shellSingleQuote(user) + " QUARANTINE_SSH_PUB=/tmp/quarantine-gateway.pub /usr/local/sbin/quarantine-harden-ssh " + shellSingleQuote(user),
	}, "; ")
	return m.sudoBashLC(inner, 2*time.Minute)
}

// linuxCopyFileTo copies a single host file to an absolute guest file path.
func (m *Manager) linuxCopyFileTo(hostPath, guestFile string) error {
	abs, err := filepath.Abs(hostPath)
	if err != nil {
		return err
	}
	user, pass := m.creds()
	auth, cleanup, err := vbox.AuthFlags(user, pass)
	if err != nil {
		return err
	}
	defer cleanup()
	args := []string{"guestcontrol", m.vmName(), "copyto"}
	args = append(args, auth...)
	args = append(args, "--target-directory="+guestFile, abs)
	_, err = m.VBox.RunWithTimeout(10*time.Minute, args...)
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
//
//	NIC1 = intnet (quarantine LAN / sample traffic via Linux gateway)
//	NIC2+ = none (no lab NAT bypass)
//
// Agent reachability is host → gateway NAT PF → DNAT to guest:9443.
func (m *Manager) AttachLabGuest() error {
	g := m.gw()
	vm := m.Cfg.VMName
	info, _ := m.VBox.RunWithTimeout(time.Minute, "showvminfo", vm, "--machinereadable")
	nic1OK := nicMachineValue(info, 1) == "intnet" && nicMachineField(info, "intnet1") == g.IntnetName
	nic2Gone := nicMachineValue(info, 2) == "none" || nicMachineValue(info, 2) == ""
	state := nicMachineField(info, "VMState")
	running := strings.EqualFold(state, "running") || strings.EqualFold(state, "paused")

	if running && nic1OK && nic2Gone {
		m.Cfg.Network.Mode = "gateway"
		m.Cfg.Network.GuestGateway = g.LANGateway
		m.Cfg.Network.GuestDNS = g.LANGateway
		return nil
	}

	if running && nic1OK && !nic2Gone {
		// Soft-disable leftover NIC without reboot when possible.
		_, _ = m.VBox.RunWithTimeout(30*time.Second, "controlvm", vm, "setlinkstate2", "off")
		m.Cfg.Network.Mode = "gateway"
		m.Cfg.Network.GuestGateway = g.LANGateway
		m.Cfg.Network.GuestDNS = g.LANGateway
		return nil
	}

	if !nic1OK || !nic2Gone {
		if running {
			_, _ = m.VBox.RunWithTimeout(2*time.Minute, "controlvm", vm, "poweroff")
			time.Sleep(2 * time.Second)
		}
		if _, err := m.VBox.RunWithTimeout(time.Minute, "modifyvm", vm,
			"--nic1", "intnet",
			"--intnet1", g.IntnetName,
			"--cableconnected1", "on",
			"--nic2", "none",
			"--nic3", "none",
			"--nic4", "none",
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
	root := m.scriptsHostDir()
	type upload struct {
		host, guest string
		required    bool
	}
	files := []upload{
		{filepath.Join(root, "nftables.conf"), "/tmp/quarantine-nftables.conf", true},
		{filepath.Join(root, "nftables-fakenet.conf"), "/tmp/quarantine-nftables-fakenet.conf", false},
		{filepath.Join(root, "nftables-permissive-forward.inc"), "/tmp/quarantine-nftables-permissive-forward.inc", false},
		{filepath.Join(root, "nftables-permissive-nat.inc"), "/tmp/quarantine-nftables-permissive-nat.inc", false},
		{filepath.Join(root, "scripts", "enable-agent-forward.sh"), "/tmp/enable-agent-forward.sh", true},
	}
	for _, f := range files {
		if _, err := os.Stat(f.host); err != nil {
			if f.required {
				return fmt.Errorf("copy %s: %w", filepath.Base(f.host), err)
			}
			continue
		}
		if err := m.linuxCopyFileTo(f.host, f.guest); err != nil {
			return fmt.Errorf("copy %s: %w", filepath.Base(f.host), err)
		}
	}
	inner := strings.Join([]string{
		"mkdir -p /opt/quarantine-gateway /etc/quarantine-gateway",
		"cp /tmp/quarantine-nftables.conf /opt/quarantine-gateway/nftables.conf",
		"[[ -f /tmp/quarantine-nftables-fakenet.conf ]] && cp /tmp/quarantine-nftables-fakenet.conf /opt/quarantine-gateway/nftables-fakenet.conf || true",
		"[[ -f /tmp/quarantine-nftables-permissive-forward.inc ]] && cp /tmp/quarantine-nftables-permissive-forward.inc /opt/quarantine-gateway/nftables-permissive-forward.inc || true",
		"[[ -f /tmp/quarantine-nftables-permissive-nat.inc ]] && cp /tmp/quarantine-nftables-permissive-nat.inc /opt/quarantine-gateway/nftables-permissive-nat.inc || true",
		"[[ -f /etc/quarantine-gateway/nftables-permissive-forward.inc ]] || { [[ -f /tmp/quarantine-nftables-permissive-forward.inc ]] && cp /tmp/quarantine-nftables-permissive-forward.inc /etc/quarantine-gateway/nftables-permissive-forward.inc; }",
		"[[ -f /etc/quarantine-gateway/nftables-permissive-nat.inc ]] || { [[ -f /tmp/quarantine-nftables-permissive-nat.inc ]] && cp /tmp/quarantine-nftables-permissive-nat.inc /etc/quarantine-gateway/nftables-permissive-nat.inc; }",
		"chmod +x /tmp/enable-agent-forward.sh",
		fmt.Sprintf("/tmp/enable-agent-forward.sh %s %d %s %s",
			g.GuestIP, port, g.LANGateway, g.LANCidr),
	}, "; ")
	out, err := m.sudoBashLC(inner, 2*time.Minute)
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

// EnsureMitmFlowCapture pushes the mitm addon/export helpers so HTTPS bodies land in flows.jsonl.
func (m *Manager) EnsureMitmFlowCapture() error {
	addon := filepath.Join(m.scriptsHostDir(), "mitm", "block_private.py")
	exportPy := filepath.Join(m.scriptsHostDir(), "mitm", "export-flows-jsonl.py")
	expl := filepath.Join(m.scriptsHostDir(), "systemd", "quarantine-mitm-explicit.service")
	trans := filepath.Join(m.scriptsHostDir(), "systemd", "quarantine-mitm-transparent.service")
	for _, pair := range [][2]string{
		{addon, "/tmp/quarantine-block_private.py"},
		{exportPy, "/tmp/quarantine-export-flows-jsonl.py"},
		{expl, "/tmp/quarantine-mitm-explicit.service"},
		{trans, "/tmp/quarantine-mitm-transparent.service"},
	} {
		if _, err := os.Stat(pair[0]); err != nil {
			continue
		}
		if err := m.linuxCopyFileTo(pair[0], pair[1]); err != nil {
			return fmt.Errorf("upload %s: %w", filepath.Base(pair[0]), err)
		}
	}
	script := `set -e
mkdir -p /usr/local/lib/quarantine /etc/quarantine-gateway /var/log/quarantine/proxy
if [ -f /tmp/quarantine-block_private.py ]; then
  install -m 0644 /tmp/quarantine-block_private.py /etc/quarantine-gateway/block_private.py
fi
if [ -f /tmp/quarantine-export-flows-jsonl.py ]; then
  install -m 0644 /tmp/quarantine-export-flows-jsonl.py /usr/local/lib/quarantine/export-flows-jsonl.py
fi
if [ -f /tmp/quarantine-mitm-explicit.service ]; then
  install -m 0644 /tmp/quarantine-mitm-explicit.service /etc/systemd/system/quarantine-mitm-explicit.service
fi
if [ -f /tmp/quarantine-mitm-transparent.service ]; then
  install -m 0644 /tmp/quarantine-mitm-transparent.service /etc/systemd/system/quarantine-mitm-transparent.service
fi
systemctl daemon-reload
# Restart only if units exist — picks up new addon env (flows.jsonl).
systemctl try-restart quarantine-mitm-explicit quarantine-mitm-transparent 2>/dev/null || true
`
	_, err := m.linuxRunWithTimeout(90*time.Second, "sudo", "bash", "-c", script)
	return err
}

// SyncGuestClock sets the gateway wall clock from the host (UTC) so proxy/pcap
// timestamps align with snapshot capturedAt used by network evidence enrichment.
func (m *Manager) SyncGuestClock() error {
	stamp := time.Now().UTC().Format("2006-01-02 15:04:05")
	script := fmt.Sprintf(`set -e
if command -v timedatectl >/dev/null 2>&1; then
  timedatectl set-ntp false 2>/dev/null || true
  timedatectl set-time '%s' 2>/dev/null || date -u -s '%s'
else
  date -u -s '%s'
fi
date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ
`, stamp, stamp, stamp)
	out, err := m.linuxRunWithTimeout(30*time.Second, "sudo", "bash", "-c", script)
	if err != nil {
		return fmt.Errorf("sync gateway clock: %w (%s)", err, strings.TrimSpace(out))
	}
	fmt.Printf("Gateway clock synced to host UTC (%s → %s)\n", stamp, strings.TrimSpace(out))
	return nil
}

// StartCapture starts tcpdump on the gateway LAN.
func (m *Manager) StartCapture() (string, error) {
	if err := m.Start(); err != nil {
		return "", err
	}
	_ = m.EnsureCaptureScripts()
	_ = m.EnsureMitmFlowCapture()
	_ = m.SyncGuestClock()
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
		cleanup += "; truncate -s 0 /var/log/quarantine/proxy/access.log /var/log/quarantine/proxy/errors.log /var/log/quarantine/proxy/access-transparent.log /var/log/quarantine/proxy/flows.jsonl /var/log/quarantine/proxy/flows-transparent.jsonl 2>/dev/null"
		cleanup += "; truncate -s 0 /var/log/quarantine/proxy/flows.mitm /var/log/quarantine/proxy/flows-transparent.mitm 2>/dev/null"
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

// CleanPcapsOpts controls gateway PCAP (and optional proxy log) cleanup.
type CleanPcapsOpts struct {
	// OlderThan deletes only files older than this age. Zero means delete all
	// non-active PCAPs under /var/log/quarantine/pcap.
	OlderThan time.Duration
	// IncludeProxy truncates rotating proxy/mitm logs (not CA certs).
	IncludeProxy bool
	// DryRun lists matching files without deleting.
	DryRun bool
}

// CleanPcaps removes old PCAPs on the gateway VM. The active capture file
// (if quarantine-capture is running) is never deleted.
func (m *Manager) CleanPcaps(opts CleanPcapsOpts) (string, error) {
	if err := m.Start(); err != nil {
		return "", err
	}

	cutoffEpoch := int64(0)
	if opts.OlderThan > 0 {
		cutoffEpoch = time.Now().Add(-opts.OlderThan).Unix()
	}
	dry := "0"
	if opts.DryRun {
		dry = "1"
	}
	proxy := "0"
	if opts.IncludeProxy {
		proxy = "1"
	}

	script := fmt.Sprintf(`set -euo pipefail
PCAP_DIR=/var/log/quarantine/pcap
PROXY_DIR=/var/log/quarantine/proxy
ACTIVE=""
if [ -f /var/run/quarantine-capture.path ]; then
  ACTIVE=$(cat /var/run/quarantine-capture.path 2>/dev/null || true)
fi
CUTOFF=%d
DRY=%s
PROXY=%s
deleted=0
kept=0
bytes=0
echo "active=${ACTIVE:-<none>}"
mkdir -p "$PCAP_DIR"
shopt -s nullglob
for f in "$PCAP_DIR"/*.pcap "$PCAP_DIR"/*.pcapng; do
  [ -f "$f" ] || continue
  if [ -n "$ACTIVE" ] && [ "$f" = "$ACTIVE" ]; then
    echo "keep active $f"
    kept=$((kept+1))
    continue
  fi
  mtime=$(stat -c %%Y "$f" 2>/dev/null || echo 0)
  if [ "$CUTOFF" -gt 0 ] && [ "$mtime" -ge "$CUTOFF" ]; then
    echo "keep recent $f"
    kept=$((kept+1))
    continue
  fi
  sz=$(stat -c %%s "$f" 2>/dev/null || echo 0)
  if [ "$DRY" = 1 ]; then
    echo "would-delete $f ($sz bytes)"
  else
    rm -f -- "$f"
    echo "deleted $f ($sz bytes)"
  fi
  deleted=$((deleted+1))
  bytes=$((bytes+sz))
done
# Staged sync leftovers in /tmp
for f in /tmp/gateway-lan-*.pcap /tmp/qproxy-bundle.tar; do
  [ -e "$f" ] || continue
  sz=$(stat -c %%s "$f" 2>/dev/null || echo 0)
  if [ "$DRY" = 1 ]; then
    echo "would-delete $f ($sz bytes)"
  else
    rm -f -- "$f"
    echo "deleted $f ($sz bytes)"
  fi
  deleted=$((deleted+1))
  bytes=$((bytes+sz))
done
if [ "$PROXY" = 1 ]; then
  for f in access.log errors.log access-transparent.log flows.jsonl flows-transparent.jsonl flows.mitm flows-transparent.mitm; do
    p="$PROXY_DIR/$f"
    [ -f "$p" ] || continue
    sz=$(stat -c %%s "$p" 2>/dev/null || echo 0)
    if [ "$DRY" = 1 ]; then
      echo "would-truncate $p ($sz bytes)"
    else
      truncate -s 0 -- "$p" 2>/dev/null || : >"$p"
      echo "truncated $p (was $sz bytes)"
    fi
    deleted=$((deleted+1))
    bytes=$((bytes+sz))
  done
fi
echo "summary deleted=$deleted kept=$kept bytes=$bytes dry=$DRY"
`, cutoffEpoch, dry, proxy)

	out, err := m.linuxRunWithTimeout(2*time.Minute, "sudo", "bash", "-c", script)
	msg := strings.TrimSpace(out)
	if err != nil {
		return msg, fmt.Errorf("clean gateway pcaps: %w (%s)", err, msg)
	}
	if msg == "" {
		msg = "Gateway PCAP cleanup complete."
	}
	return msg, nil
}

// ExportCA copies the mitm CA to network/proxy for guest install.
func (m *Manager) ExportCA() (string, error) {
	if err := m.Start(); err != nil {
		return "", err
	}
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
	if out, err := m.sudoBashLC(inner, 2*time.Minute); err != nil {
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
