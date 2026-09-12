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
	"github.com/quarantine-lab/quarantine/internal/guest"
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
	if err := m.uploadPermissivePolicy(); err != nil {
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
	if persistErr := m.persistGatewaySettings(); persistErr != nil && msg != "" {
		msg += "\n(config persist: " + persistErr.Error() + ")"
	} else if persistErr != nil {
		msg = persistErr.Error()
	}
	if msg == "" {
		msg = "traffic-mode=" + norm
	}
	note, verr := m.verifyGuestHTTPS(norm)
	if note != "" {
		msg += "\n" + note
	}
	if verr != nil {
		// Gateway already switched and config persisted. A failed guest probe must not
		// undo that in the UI (alert made it look like FakeNet/permissive never applied).
		msg += "\nWARNING: " + verr.Error()
	}
	return msg, nil
}

// verifyGuestHTTPS checks MITM from the lab VM when it is running.
// A powered-off guest must not fail a successful gateway switch.
func (m *Manager) verifyGuestHTTPS(mode string) (string, error) {
	running, state, err := m.windowsGuestState()
	if err != nil {
		return "Windows guest HTTPS check skipped: " + err.Error(), nil
	}
	if !running {
		return "Windows guest HTTPS check skipped (lab VM is " + state + ")", nil
	}
	switch mode {
	case "fakenet":
		if gerr := m.testFakeNetGuestBrowser(); gerr != nil {
			return "", fmt.Errorf("Windows guest HTTPS (Chrome path): %w", gerr)
		}
		return "Windows guest CONNECT+TLS: ok", nil
	case "permissive":
		if gerr := m.testPermissiveGuestHttps(); gerr != nil {
			return "", fmt.Errorf("Windows guest HTTPS (curl transparent MITM): %w", gerr)
		}
		return "Windows guest curl --noproxy MITM: ok", nil
	}
	return "", nil
}

func (m *Manager) windowsGuestState() (running bool, state string, err error) {
	win := strings.TrimSpace(m.Cfg.VMName)
	if win == "" {
		return false, "", fmt.Errorf("config vmName is empty")
	}
	state, err = m.VBox.VMState(win)
	if err != nil {
		return false, "", fmt.Errorf("Windows VM %q: %w", win, err)
	}
	return strings.EqualFold(state, "running"), state, nil
}

// testFakeNetGuestBrowser runs CONNECT+TLS inside the Windows VM (same path as Edge/Chrome).
func (m *Manager) testFakeNetGuestBrowser() error {
	script := filepath.Join(m.ProjectRoot, "network", "guest", "Test-FakeNetBrowserHttps.ps1")
	script, err := filepath.Abs(script)
	if err != nil {
		return fmt.Errorf("guest HTTPS test path: %w", err)
	}
	if _, err := os.Stat(script); err != nil {
		return fmt.Errorf("missing %s: %w", script, err)
	}
	g := guest.New(m.Cfg, m.VBox)
	dest := `C:\Users\Public\Quarantine\Test-FakeNetBrowserHttps.ps1`
	if err := g.CopyToDest(script, dest); err != nil {
		return fmt.Errorf("upload guest HTTPS test: %w", err)
	}
	out, err := g.RunPowerShell(dest, nil, g.GuestCreds())
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
	script := filepath.Join(m.ProjectRoot, "network", "guest", "Test-PermissiveHttps.ps1")
	script, err := filepath.Abs(script)
	if err != nil {
		return fmt.Errorf("guest HTTPS test path: %w", err)
	}
	if _, err := os.Stat(script); err != nil {
		return fmt.Errorf("missing %s: %w", script, err)
	}
	g := guest.New(m.Cfg, m.VBox)
	dest := `C:\Users\Public\Quarantine\Test-PermissiveHttps.ps1`
	if err := g.CopyToDest(script, dest); err != nil {
		return fmt.Errorf("upload guest HTTPS test: %w", err)
	}
	out, err := g.RunPowerShell(dest, nil, g.GuestCreds())
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
		{filepath.Join(root, "nftables-emergency.conf"), "/tmp/quarantine-nftables-emergency.conf"},
		{filepath.Join(root, "nftables-permissive-forward.inc"), "/tmp/quarantine-nftables-permissive-forward.inc"},
		{filepath.Join(root, "nftables-permissive-nat.inc"), "/tmp/quarantine-nftables-permissive-nat.inc"},
		{filepath.Join(root, "nftables-permissive-output.inc"), "/tmp/quarantine-nftables-permissive-output.inc"},
		{filepath.Join(root, "scripts", "nft-inject-permissive.py"), "/tmp/nft-inject-permissive.py"},
		{filepath.Join(root, "scripts", "ensure-service-users.sh"), "/tmp/quarantine-ensure-service-users.sh"},
		{filepath.Join(root, "fakenet", "quarantine.ini"), "/tmp/quarantine-fakenet.ini"},
		{filepath.Join(root, "fakenet", "ssl_utils_init.py"), "/tmp/quarantine-fakenet-ssl_utils.py"},
		{filepath.Join(root, "fakenet", "patch_httplistener.py"), "/tmp/quarantine-fakenet-patch_httplistener.py"},
		{filepath.Join(root, "fakenet", "patch_diverter_privcheck.py"), "/tmp/quarantine-fakenet-patch_diverter_privcheck.py"},
		{filepath.Join(root, "fakenet", "HTTPListener.py"), "/tmp/quarantine-fakenet-HTTPListener.py"},
		{filepath.Join(root, "fakenet", "test_connect_proxy.py"), "/tmp/quarantine-fakenet-test_connect_proxy.py"},
		{filepath.Join(root, "systemd", "quarantine-fakenet.service"), "/tmp/quarantine-fakenet.service"},
		{filepath.Join(root, "systemd", "quarantine-fakenet-proxy.service"), "/tmp/quarantine-fakenet-proxy.service"},
		{filepath.Join(root, "systemd", "quarantine-mitm-explicit.service"), "/tmp/quarantine-mitm-explicit.service"},
		{filepath.Join(root, "systemd", "quarantine-mitm-transparent.service"), "/tmp/quarantine-mitm-transparent.service"},
		{filepath.Join(root, "systemd", "quarantine-capture.service"), "/tmp/quarantine-capture.service"},
		{filepath.Join(root, "systemd", "quarantine-traffic-mode.service"), "/tmp/quarantine-traffic-mode.service"},
		{filepath.Join(root, "scripts", "status.sh"), "/tmp/quarantine-gateway-status.sh"},
		{filepath.Join(root, "scripts", "fakenet-explicit-proxy.py"), "/tmp/quarantine-fakenet-explicit-proxy.py"},
		{filepath.Join(root, "scripts", "start-capture.sh"), "/tmp/quarantine-capture-start.sh"},
		{filepath.Join(root, "scripts", "stop-capture.sh"), "/tmp/quarantine-capture-stop.sh"},
		{filepath.Join(root, "scripts", "export-ca.sh"), "/tmp/quarantine-export-ca.sh"},
		{filepath.Join(root, "python", "fakenet-source.pin"), "/tmp/quarantine-fakenet-source.pin"},
		{filepath.Join(root, "python", "requirements-fakenet.txt"), "/tmp/quarantine-requirements-fakenet.txt"},
		{filepath.Join(root, "python", "requirements-mitm.txt"), "/tmp/quarantine-requirements-mitm.txt"},
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
mkdir -p /opt/quarantine-gateway/scripts /opt/quarantine-gateway/fakenet /opt/quarantine-gateway/python /var/log/quarantine/fakenet /etc/quarantine-gateway /usr/local/lib/quarantine
install -m 0755 /tmp/quarantine-set-traffic-mode.sh /usr/local/sbin/quarantine-set-traffic-mode
install -m 0755 /tmp/quarantine-install-fakenet.sh /usr/local/sbin/quarantine-install-fakenet
install -m 0755 /tmp/quarantine-repair-wan-dns.sh /usr/local/sbin/quarantine-repair-wan-dns
install -m 0755 /tmp/quarantine-gateway-status.sh /usr/local/sbin/quarantine-gateway-status
install -m 0755 /tmp/quarantine-ensure-service-users.sh /usr/local/sbin/quarantine-ensure-service-users
install -m 0755 /tmp/nft-inject-permissive.py /opt/quarantine-gateway/scripts/nft-inject-permissive.py
install -m 0755 /tmp/nft-inject-permissive.py /usr/local/lib/quarantine/nft-inject-permissive.py
install -m 0755 /tmp/quarantine-capture-start.sh /usr/local/sbin/quarantine-capture-start
install -m 0755 /tmp/quarantine-capture-stop.sh /usr/local/sbin/quarantine-capture-stop
install -m 0755 /tmp/quarantine-export-ca.sh /usr/local/sbin/quarantine-export-ca 2>/dev/null || true
install -m 0644 /tmp/quarantine-nftables.conf /opt/quarantine-gateway/nftables.conf
install -m 0644 /tmp/quarantine-nftables-fakenet.conf /opt/quarantine-gateway/nftables-fakenet.conf
install -m 0644 /tmp/quarantine-nftables-emergency.conf /opt/quarantine-gateway/nftables-emergency.conf
install -m 0644 /tmp/quarantine-nftables-permissive-forward.inc /opt/quarantine-gateway/nftables-permissive-forward.inc
install -m 0644 /tmp/quarantine-nftables-permissive-nat.inc /opt/quarantine-gateway/nftables-permissive-nat.inc
install -m 0644 /tmp/quarantine-nftables-permissive-output.inc /opt/quarantine-gateway/nftables-permissive-output.inc
install -m 0644 /tmp/quarantine-nftables-permissive-forward.inc /etc/quarantine-gateway/nftables-permissive-forward.inc
install -m 0644 /tmp/quarantine-nftables-permissive-nat.inc /etc/quarantine-gateway/nftables-permissive-nat.inc
install -m 0644 /tmp/quarantine-nftables-permissive-output.inc /etc/quarantine-gateway/nftables-permissive-output.inc
install -m 0644 /tmp/quarantine-fakenet.ini /opt/quarantine-gateway/fakenet/quarantine.ini
install -m 0644 /tmp/quarantine-fakenet-ssl_utils.py /opt/quarantine-gateway/fakenet/ssl_utils_init.py
install -m 0644 /tmp/quarantine-fakenet-patch_httplistener.py /opt/quarantine-gateway/fakenet/patch_httplistener.py
install -m 0644 /tmp/quarantine-fakenet-patch_diverter_privcheck.py /opt/quarantine-gateway/fakenet/patch_diverter_privcheck.py
install -m 0644 /tmp/quarantine-fakenet-HTTPListener.py /opt/quarantine-gateway/fakenet/HTTPListener.py
install -m 0644 /tmp/quarantine-fakenet-test_connect_proxy.py /opt/quarantine-gateway/fakenet/test_connect_proxy.py
install -m 0644 /tmp/quarantine-fakenet-source.pin /opt/quarantine-gateway/python/fakenet-source.pin
install -m 0644 /tmp/quarantine-requirements-fakenet.txt /opt/quarantine-gateway/python/requirements-fakenet.txt
install -m 0644 /tmp/quarantine-requirements-mitm.txt /opt/quarantine-gateway/python/requirements-mitm.txt
cp /tmp/quarantine-install-fakenet.sh /opt/quarantine-gateway/scripts/install-fakenet.sh
cp /tmp/quarantine-repair-wan-dns.sh /opt/quarantine-gateway/scripts/repair-wan-dns.sh
cp /tmp/quarantine-ensure-service-users.sh /opt/quarantine-gateway/scripts/ensure-service-users.sh
install -m 0644 /tmp/quarantine-fakenet.service /etc/systemd/system/quarantine-fakenet.service
install -m 0644 /tmp/quarantine-fakenet-proxy.service /etc/systemd/system/quarantine-fakenet-proxy.service
install -m 0644 /tmp/quarantine-mitm-explicit.service /etc/systemd/system/quarantine-mitm-explicit.service
install -m 0644 /tmp/quarantine-mitm-transparent.service /etc/systemd/system/quarantine-mitm-transparent.service
install -m 0644 /tmp/quarantine-capture.service /etc/systemd/system/quarantine-capture.service
install -m 0755 /tmp/quarantine-fakenet-explicit-proxy.py /usr/local/sbin/quarantine-fakenet-explicit-proxy
install -m 0644 /tmp/quarantine-traffic-mode.service /etc/systemd/system/quarantine-traffic-mode.service
/usr/local/sbin/quarantine-ensure-service-users || true
systemctl daemon-reload
systemctl enable quarantine-traffic-mode >/dev/null 2>&1 || true
`
	_, err := m.linuxRunWithTimeout(60*time.Second, "sudo", "bash", "-c", script)
	return err
}

func (m *Manager) uploadPermissivePolicy() error {
	g := m.gw()
	pol := g.Permissive.WithDefaults()
	m.Cfg.Network.Gateway.Permissive = pol
	dir := os.TempDir()
	policyPath := filepath.Join(dir, "qlab-permissive-policy.json")
	fwdPath := filepath.Join(dir, "qlab-nft-forward.inc")
	natPath := filepath.Join(dir, "qlab-nft-nat.inc")
	outPath := filepath.Join(dir, "qlab-nft-output.inc")
	raw, err := json.MarshalIndent(pol, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(policyPath, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(fwdPath, []byte(pol.PermissiveForwardRules()), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(natPath, []byte(pol.PermissiveNATRules()), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(outPath, []byte(pol.PermissiveOutputRules()), 0o600); err != nil {
		return err
	}
	defer os.Remove(policyPath)
	defer os.Remove(fwdPath)
	defer os.Remove(natPath)
	defer os.Remove(outPath)
	if err := m.linuxCopyFileTo(policyPath, "/tmp/quarantine-permissive-policy.json"); err != nil {
		return fmt.Errorf("upload permissive policy: %w", err)
	}
	if err := m.linuxCopyFileTo(fwdPath, "/tmp/quarantine-nftables-permissive-forward.inc"); err != nil {
		return fmt.Errorf("upload nft forward snippet: %w", err)
	}
	if err := m.linuxCopyFileTo(natPath, "/tmp/quarantine-nftables-permissive-nat.inc"); err != nil {
		return fmt.Errorf("upload nft nat snippet: %w", err)
	}
	if err := m.linuxCopyFileTo(outPath, "/tmp/quarantine-nftables-permissive-output.inc"); err != nil {
		return fmt.Errorf("upload nft output snippet: %w", err)
	}
	script := `set -e
mkdir -p /etc/quarantine-gateway
install -m 0644 /tmp/quarantine-permissive-policy.json /etc/quarantine-gateway/permissive-policy.json
install -m 0644 /tmp/quarantine-nftables-permissive-forward.inc /etc/quarantine-gateway/nftables-permissive-forward.inc
install -m 0644 /tmp/quarantine-nftables-permissive-nat.inc /etc/quarantine-gateway/nftables-permissive-nat.inc
install -m 0644 /tmp/quarantine-nftables-permissive-output.inc /etc/quarantine-gateway/nftables-permissive-output.inc
`
	_, err = m.linuxRunWithTimeout(45*time.Second, "sudo", "bash", "-c", script)
	return err
}

func (m *Manager) persistGatewaySettings() error {
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
	g := m.gw()
	gwObj["trafficMode"] = g.TrafficMode
	gwObj["permissive"] = g.Permissive.WithDefaults()
	gwObj["enabled"] = true
	gwObj["password"] = ""
	if g.PasswordFile != "" {
		gwObj["passwordFile"] = g.PasswordFile
	}
	if g.SSHPrivateKey != "" {
		gwObj["sshPrivateKey"] = g.SSHPrivateKey
	}
	if g.SSHPublicKey != "" {
		gwObj["sshPublicKey"] = g.SSHPublicKey
	}
	netObj["mode"] = "gateway"
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0o644)
}

// ApplyPermissivePolicy uploads nft snippets and reapplies permissive mode when it is active.
func (m *Manager) ApplyPermissivePolicy() (string, error) {
	m.Cfg.Network.Gateway.Permissive = m.gw().Permissive.WithDefaults()
	if err := m.persistGatewaySettings(); err != nil {
		return "", err
	}
	if err := m.Start(); err != nil {
		return "saved locally", fmt.Errorf("saved allowlist; gateway not reachable: %w", err)
	}
	if err := m.EnsureTrafficModeScripts(); err != nil {
		return "", err
	}
	if err := m.uploadPermissivePolicy(); err != nil {
		return "", err
	}
	mode := m.gw().TrafficMode
	if mode != "permissive" {
		return "saved (active after next Permissive switch; current mode=" + mode + ")", nil
	}
	out, err := m.linuxRunWithTimeout(3*time.Minute, "sudo", "/usr/local/sbin/quarantine-set-traffic-mode", "permissive")
	msg := strings.TrimSpace(out)
	if err != nil {
		return msg, fmt.Errorf("apply permissive policy: %w (%s)", err, msg)
	}
	return msg, nil
}
