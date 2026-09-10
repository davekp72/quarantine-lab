package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quarantine-lab/quarantine/internal/config"
)

// SetTrafficMode switches the Linux gateway between permissive MITM and FakeNet sinkhole.
func (m *Manager) SetTrafficMode(mode string) (string, error) {
	norm, err := config.NormalizeTrafficMode(mode)
	if err != nil {
		return "", err
	}
	if err := m.Start(); err != nil {
		return "", err
	}
	if err := m.EnsureTrafficModeScripts(); err != nil {
		return "", err
	}
	if norm == "fakenet" {
		if err := m.EnsureFakeNetInstalled(); err != nil {
			return "", err
		}
		_ = m.SyncGuestClock()
	}
	out, err := m.linuxRunWithTimeout(3*time.Minute, "sudo", "/usr/local/sbin/quarantine-set-traffic-mode", norm)
	msg := strings.TrimSpace(out)
	if err != nil {
		return msg, fmt.Errorf("set traffic mode %s: %w (%s)", norm, err, msg)
	}
	m.Cfg.Network.Gateway.TrafficMode = norm
	if persistErr := m.persistTrafficMode(norm); persistErr != nil && msg != "" {
		msg += "\n(config persist: " + persistErr.Error() + ")"
	} else if persistErr != nil {
		msg = persistErr.Error()
	}
	if msg == "" {
		msg = "traffic-mode=" + norm
	}
	if norm == "fakenet" {
		if gerr := m.testFakeNetGuestBrowser(); gerr != nil {
			return msg, fmt.Errorf("Windows guest HTTPS (Chrome path): %w", gerr)
		}
		msg += "\nWindows guest CONNECT+TLS: ok"
	}
	if norm == "permissive" {
		if gerr := m.testPermissiveGuestHttps(); gerr != nil {
			return msg, fmt.Errorf("Windows guest HTTPS (curl transparent MITM): %w", gerr)
		}
		msg += "\nWindows guest curl --noproxy MITM: ok"
	}
	return msg, nil
}

// testFakeNetGuestBrowser runs CONNECT+TLS inside the Windows VM (same path as Edge/Chrome).
func (m *Manager) testFakeNetGuestBrowser() error {
	win := strings.TrimSpace(m.Cfg.VMName)
	if win == "" {
		return fmt.Errorf("config vmName is empty")
	}
	state, err := m.VBox.VMState(win)
	if err != nil {
		return fmt.Errorf("Windows VM %q: %w", win, err)
	}
	if !strings.EqualFold(state, "running") {
		return fmt.Errorf("Windows VM %q is %s (start it to verify browser HTTPS)", win, state)
	}
	script := filepath.Join(m.ProjectRoot, "network", "guest", "Test-FakeNetBrowserHttps.ps1")
	script, err = filepath.Abs(script)
	if err != nil {
		return fmt.Errorf("guest HTTPS test path: %w", err)
	}
	if _, err := os.Stat(script); err != nil {
		return fmt.Errorf("missing %s: %w", script, err)
	}
	user := m.Cfg.Guest.Username
	pass := m.Cfg.Guest.Password
	dest := `C:\Users\Public\Quarantine\Test-FakeNetBrowserHttps.ps1`
	if err := m.VBox.GuestControlCopyTo(win, user, pass, script, dest, 45*time.Second); err != nil {
		return fmt.Errorf("upload guest HTTPS test: %w", err)
	}
	out, err := m.VBox.GuestControlRun(
		win, user, pass,
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		[]string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", dest},
		90*time.Second,
	)
	msg := strings.TrimSpace(out)
	if err != nil {
		return fmt.Errorf("%w (%s)", err, msg)
	}
	if !strings.Contains(msg, "result=browser-https-ok") {
		return fmt.Errorf("guest HTTPS test did not pass:\n%s", msg)
	}
	return nil
}

func (m *Manager) testPermissiveGuestHttps() error {
	win := strings.TrimSpace(m.Cfg.VMName)
	if win == "" {
		return fmt.Errorf("config vmName is empty")
	}
	state, err := m.VBox.VMState(win)
	if err != nil {
		return fmt.Errorf("Windows VM %q: %w", win, err)
	}
	if !strings.EqualFold(state, "running") {
		return fmt.Errorf("Windows VM %q is %s (start it to verify curl HTTPS)", win, state)
	}
	script := filepath.Join(m.ProjectRoot, "network", "guest", "Test-PermissiveHttps.ps1")
	script, err = filepath.Abs(script)
	if err != nil {
		return fmt.Errorf("guest HTTPS test path: %w", err)
	}
	if _, err := os.Stat(script); err != nil {
		return fmt.Errorf("missing %s: %w", script, err)
	}
	user := m.Cfg.Guest.Username
	pass := m.Cfg.Guest.Password
	dest := `C:\Users\Public\Quarantine\Test-PermissiveHttps.ps1`
	if err := m.VBox.GuestControlCopyTo(win, user, pass, script, dest, 45*time.Second); err != nil {
		return fmt.Errorf("upload guest HTTPS test: %w", err)
	}
	out, err := m.VBox.GuestControlRun(
		win, user, pass,
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		[]string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", dest},
		90*time.Second,
	)
	msg := strings.TrimSpace(out)
	if err != nil {
		return fmt.Errorf("%w (%s)", err, msg)
	}
	if !strings.Contains(msg, "result=permissive-transparent-ok") {
		return fmt.Errorf("guest curl transparent MITM test did not pass:\n%s", msg)
	}
	if !strings.Contains(strings.ToLower(msg), "mitmproxy") {
		return fmt.Errorf("direct :443 was not MITM'd (issuer missing mitmproxy):\n%s", msg)
	}
	return nil
}

// EnsureFakeNetInstalled installs FakeNet-NG into the gateway venv when missing.
func (m *Manager) EnsureFakeNetInstalled() error {
	check := `if [[ -x /opt/quarantine-gateway/venv-fakenet/bin/python ]] && /opt/quarantine-gateway/venv-fakenet/bin/python -c 'import fakenet, netfilterqueue, netifaces' >/dev/null 2>&1; then echo FAKENET_OK; else echo FAKENET_MISSING; fi`
	out, err := m.linuxRunWithTimeout(45*time.Second, "sudo", "bash", "-c", check)
	status := strings.TrimSpace(out)
	if err == nil && strings.Contains(status, "FAKENET_OK") && !strings.Contains(status, "FAKENET_MISSING") {
		return nil
	}
	out, err = m.linuxRunWithTimeout(15*time.Minute, "sudo", "/usr/local/sbin/quarantine-install-fakenet")
	msg := strings.TrimSpace(out)
	if err != nil {
		return fmt.Errorf("install FakeNet on gateway (needs WAN DNS + libnetfilter-queue-dev): %w (%s)", err, msg)
	}
	// Re-check after install
	out, err = m.linuxRunWithTimeout(45*time.Second, "sudo", "bash", "-c", check)
	status = strings.TrimSpace(out)
	if err != nil || !strings.Contains(status, "FAKENET_OK") {
		return fmt.Errorf("FakeNet still missing after install (%s)", status)
	}
	return nil
}

// TrafficMode reports the mode file on the gateway (guestcontrol — CLI only, not UI idle poll).
func (m *Manager) TrafficMode() (string, string, error) {
	state, err := m.VBox.VMState(m.vmName())
	if err != nil {
		return "", "", err
	}
	if !strings.EqualFold(state, "running") {
		g := m.gw()
		return g.TrafficMode, fmt.Sprintf("gateway not running (config=%s)", g.TrafficMode), nil
	}
	out, err := m.linuxRunWithTimeout(45*time.Second, "sudo", "/usr/local/sbin/quarantine-set-traffic-mode", "status")
	msg := strings.TrimSpace(out)
	if err != nil {
		return m.gw().TrafficMode, msg, err
	}
	mode := m.gw().TrafficMode
	for _, line := range strings.Split(msg, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "traffic-mode=") {
			mode = strings.TrimSpace(strings.TrimPrefix(line, "traffic-mode="))
			break
		}
	}
	if norm, nerr := config.NormalizeTrafficMode(mode); nerr == nil {
		mode = norm
		m.Cfg.Network.Gateway.TrafficMode = mode
	}
	return mode, msg, nil
}

// EnsureTrafficModeScripts uploads switcher + FakeNet templates (venv still needs provision).
func (m *Manager) EnsureTrafficModeScripts() error {
	root := m.scriptsHostDir()
	pairs := [][2]string{
		{filepath.Join(root, "scripts", "set-traffic-mode.sh"), "/tmp/quarantine-set-traffic-mode.sh"},
		{filepath.Join(root, "scripts", "install-fakenet.sh"), "/tmp/quarantine-install-fakenet.sh"},
		{filepath.Join(root, "scripts", "repair-wan-dns.sh"), "/tmp/quarantine-repair-wan-dns.sh"},
		{filepath.Join(root, "nftables.conf"), "/tmp/quarantine-nftables.conf"},
		{filepath.Join(root, "nftables-fakenet.conf"), "/tmp/quarantine-nftables-fakenet.conf"},
		{filepath.Join(root, "fakenet", "quarantine.ini"), "/tmp/quarantine-fakenet.ini"},
		{filepath.Join(root, "fakenet", "ssl_utils_init.py"), "/tmp/quarantine-fakenet-ssl_utils.py"},
		{filepath.Join(root, "fakenet", "patch_httplistener.py"), "/tmp/quarantine-fakenet-patch_httplistener.py"},
		{filepath.Join(root, "fakenet", "HTTPListener.py"), "/tmp/quarantine-fakenet-HTTPListener.py"},
		{filepath.Join(root, "fakenet", "test_connect_proxy.py"), "/tmp/quarantine-fakenet-test_connect_proxy.py"},
		{filepath.Join(root, "systemd", "quarantine-fakenet.service"), "/tmp/quarantine-fakenet.service"},
		{filepath.Join(root, "systemd", "quarantine-fakenet-proxy.service"), "/tmp/quarantine-fakenet-proxy.service"},
		{filepath.Join(root, "systemd", "quarantine-mitm-explicit.service"), "/tmp/quarantine-mitm-explicit.service"},
		{filepath.Join(root, "systemd", "quarantine-mitm-transparent.service"), "/tmp/quarantine-mitm-transparent.service"},
		{filepath.Join(root, "systemd", "quarantine-traffic-mode.service"), "/tmp/quarantine-traffic-mode.service"},
		{filepath.Join(root, "scripts", "status.sh"), "/tmp/quarantine-gateway-status.sh"},
		{filepath.Join(root, "scripts", "fakenet-explicit-proxy.py"), "/tmp/quarantine-fakenet-explicit-proxy.py"},
	}
	for _, pair := range pairs {
		if _, err := os.Stat(pair[0]); err != nil {
			return fmt.Errorf("missing %s: %w", filepath.Base(pair[0]), err)
		}
		if err := m.linuxCopyFileTo(pair[0], pair[1]); err != nil {
			return fmt.Errorf("upload %s: %w", filepath.Base(pair[0]), err)
		}
	}
	script := `set -e
mkdir -p /opt/quarantine-gateway/scripts /opt/quarantine-gateway/fakenet /var/log/quarantine/fakenet /etc/quarantine-gateway
install -m 0755 /tmp/quarantine-set-traffic-mode.sh /usr/local/sbin/quarantine-set-traffic-mode
install -m 0755 /tmp/quarantine-install-fakenet.sh /usr/local/sbin/quarantine-install-fakenet
install -m 0755 /tmp/quarantine-repair-wan-dns.sh /usr/local/sbin/quarantine-repair-wan-dns
install -m 0755 /tmp/quarantine-gateway-status.sh /usr/local/sbin/quarantine-gateway-status
install -m 0644 /tmp/quarantine-nftables.conf /opt/quarantine-gateway/nftables.conf
install -m 0644 /tmp/quarantine-nftables-fakenet.conf /opt/quarantine-gateway/nftables-fakenet.conf
install -m 0644 /tmp/quarantine-fakenet.ini /opt/quarantine-gateway/fakenet/quarantine.ini
install -m 0644 /tmp/quarantine-fakenet-ssl_utils.py /opt/quarantine-gateway/fakenet/ssl_utils_init.py
install -m 0644 /tmp/quarantine-fakenet-patch_httplistener.py /opt/quarantine-gateway/fakenet/patch_httplistener.py
install -m 0644 /tmp/quarantine-fakenet-HTTPListener.py /opt/quarantine-gateway/fakenet/HTTPListener.py
install -m 0644 /tmp/quarantine-fakenet-test_connect_proxy.py /opt/quarantine-gateway/fakenet/test_connect_proxy.py
cp /tmp/quarantine-install-fakenet.sh /opt/quarantine-gateway/scripts/install-fakenet.sh
cp /tmp/quarantine-repair-wan-dns.sh /opt/quarantine-gateway/scripts/repair-wan-dns.sh
install -m 0644 /tmp/quarantine-fakenet.service /etc/systemd/system/quarantine-fakenet.service
install -m 0644 /tmp/quarantine-fakenet-proxy.service /etc/systemd/system/quarantine-fakenet-proxy.service
install -m 0644 /tmp/quarantine-mitm-explicit.service /etc/systemd/system/quarantine-mitm-explicit.service
install -m 0644 /tmp/quarantine-mitm-transparent.service /etc/systemd/system/quarantine-mitm-transparent.service
install -m 0755 /tmp/quarantine-fakenet-explicit-proxy.py /usr/local/sbin/quarantine-fakenet-explicit-proxy
install -m 0644 /tmp/quarantine-traffic-mode.service /etc/systemd/system/quarantine-traffic-mode.service
systemctl daemon-reload
systemctl enable quarantine-traffic-mode >/dev/null 2>&1 || true
`
	_, err := m.linuxRunWithTimeout(60*time.Second, "sudo", "bash", "-c", script)
	return err
}

func (m *Manager) persistTrafficMode(mode string) error {
	path := strings.TrimSpace(m.CfgPath)
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	netObj, _ := doc["network"].(map[string]any)
	if netObj == nil {
		netObj = map[string]any{}
		doc["network"] = netObj
	}
	gwObj, _ := netObj["gateway"].(map[string]any)
	if gwObj == nil {
		gwObj = map[string]any{}
		netObj["gateway"] = gwObj
	}
	gwObj["trafficMode"] = mode
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0o644)
}
