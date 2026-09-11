package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsKnownDefaultPassword(t *testing.T) {
	if !IsKnownDefaultPassword("quarantine") {
		t.Fatal("expected quarantine default")
	}
	if !IsKnownDefaultPassword("ChangeMe-Quarantine!") {
		t.Fatal("expected ChangeMe default")
	}
	if IsKnownDefaultPassword("a-unique-lab-pass-9X") {
		t.Fatal("unique password must not be treated as default")
	}
}

func TestGeneratePassword(t *testing.T) {
	a, err := GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("expected unique passwords")
	}
	if len(a) < 16 || IsKnownDefaultPassword(a) {
		t.Fatalf("weak password %q", a)
	}
}

func TestPreflightRejectsDefaults(t *testing.T) {
	cfg := &Config{
		VMDataDir: t.TempDir(),
		Guest:     AccountConfig{Username: "quarantine", Password: "quarantine"},
		Network:   NetworkConfig{Mode: "gateway", Gateway: GatewayConfig{Enabled: true, Password: "quarantine"}},
	}
	if err := cfg.PreflightCredentials(); err == nil {
		t.Fatal("expected preflight failure")
	}
}

func TestEnsureSecretsGeneratesAndRenders(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.json")
	project := t.TempDir()
	tmplDir := filepath.Join(project, "templates")
	cloudDir := filepath.Join(project, "gateway", "cloud-init")
	if err := os.MkdirAll(tmplDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cloudDir, 0o755); err != nil {
		t.Fatal(err)
	}
	unattend := []byte(`<Password><Value>__GUEST_PASSWORD__</Value></Password>
<Name>__GUEST_USERNAME__</Name>
<Name>__PAYLOAD_USERNAME__</Name>
<Value>__PAYLOAD_PASSWORD__</Value>`)
	if err := os.WriteFile(filepath.Join(tmplDir, "autounattend.xml"), unattend, 0o644); err != nil {
		t.Fatal(err)
	}
	userData := []byte(`#cloud-config
users:
  - name: __GATEWAY_USER__
    sudo: ALL=(ALL) ALL
    passwd: '__GATEWAY_PASSWORD_HASH__'
    ssh_authorized_keys:
      - __GATEWAY_SSH_PUBKEY__
ssh_pwauth: false
`)
	if err := os.WriteFile(filepath.Join(cloudDir, "user-data"), userData, 0o644); err != nil {
		t.Fatal(err)
	}
	raw := `{
		"vmName": "TestVM",
		"vmDataDir": "` + strings.ReplaceAll(dir, `\`, `\\`) + `",
		"autounattendPath": "` + strings.ReplaceAll(filepath.Join(tmplDir, "autounattend.xml"), `\`, `\\`) + `",
		"guest": {"username": "quarantine", "password": ""},
		"payload": {"username": "analyst", "password": ""},
		"network": {"mode": "gateway", "gateway": {"enabled": true, "username": "quarantine"}}
	}`
	if err := os.WriteFile(cfgPath, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.EnsureSecrets(cfgPath, project, true); err != nil {
		t.Fatal(err)
	}
	if err := cfg.PreflightCredentials(); err != nil {
		t.Fatal(err)
	}
	if IsKnownDefaultPassword(cfg.Guest.Password) || IsKnownDefaultPassword(cfg.Network.Gateway.Password) {
		t.Fatal("generated a known default")
	}
	unattendOut, err := os.ReadFile(cfg.AutounattendPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(unattendOut)), "changeme") {
		t.Fatal("rendered unattend still has default")
	}
	if strings.Contains(string(unattendOut), "__GUEST_PASSWORD__") {
		t.Fatal("placeholder left in unattend")
	}
}
