package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadExample(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	path := filepath.Join(root, "config", "quarantine-vm.json")
	if _, err := os.Stat(path); err != nil {
		t.Skip("config not present in workspace")
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VMName == "" {
		t.Fatal("expected vmName")
	}
	if cfg.DataDir() == "" {
		t.Fatal("expected data dir")
	}
	if cfg.DiskPathResolved() == "" {
		t.Fatal("expected disk path")
	}
}

func TestAgentGuestInstallPathAvoidsProgramFiles(t *testing.T) {
	c := &Config{}
	got := c.AgentGuestInstallPath()
	if strings.Contains(strings.ToLower(got), `\program files`) {
		t.Fatalf("staging path must be guestcontrol-writable, got %s", got)
	}
	if strings.Contains(strings.ToLower(got), `\programdata\`) {
		t.Fatalf("staging path must not be under ACL'd ProgramData, got %s", got)
	}
	c.Agent.InstallPath = `C:\Program Files\QuarantineLab\quarantine-agent.exe`
	got = c.AgentGuestInstallPath()
	if strings.Contains(strings.ToLower(got), `\program files`) {
		t.Fatalf("Program Files installPath must remap to staging, got %s", got)
	}
}

func TestLoadRemapsHostNatNotIntnet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.json")
	raw := `{
		"vmName": "TestVM",
		"vmDataDir": "` + strings.ReplaceAll(dir, `\`, `\\`) + `",
		"network": {"mode": "host-nat", "gateway": {"enabled": false}}
	}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Network.Mode != "gateway" {
		t.Fatalf("host-nat: mode=%q", cfg.Network.Mode)
	}
	if !cfg.Network.Gateway.Enabled {
		t.Fatal("host-nat should enable gateway")
	}
	if cfg.Network.Gateway.TrafficMode != "fakenet" {
		t.Fatalf("trafficMode=%q", cfg.Network.Gateway.TrafficMode)
	}

	raw = `{
		"vmName": "TestVM",
		"vmDataDir": "` + strings.ReplaceAll(dir, `\`, `\\`) + `",
		"network": {"mode": "intnet", "gateway": {"enabled": false}}
	}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Network.Mode != "intnet" {
		t.Fatalf("intnet should stay offline isolation, got %q", cfg.Network.Mode)
	}
}

func TestNormalizeTrafficMode(t *testing.T) {
	got, err := NormalizeTrafficMode("")
	if err != nil || got != "fakenet" {
		t.Fatalf("empty: got %q %v", got, err)
	}
	got, err = NormalizeTrafficMode("FakeNet")
	if err != nil || got != "fakenet" {
		t.Fatalf("fakenet: got %q %v", got, err)
	}
	got, err = NormalizeTrafficMode("permissive")
	if err != nil || got != "permissive" {
		t.Fatalf("permissive: got %q %v", got, err)
	}
	if _, err := NormalizeTrafficMode("nope"); err == nil {
		t.Fatal("expected error")
	}
}

func TestFilePreviewMaxKB(t *testing.T) {
	var nilCfg *Config
	if nilCfg.FilePreviewMaxKBResolved() != DefaultFilePreviewMaxKB {
		t.Fatal("nil default")
	}
	c := &Config{UI: UIConfig{FilePreviewMaxKB: 1024}}
	if c.FilePreviewMaxBytes() != 1024*1024 {
		t.Fatalf("bytes=%d", c.FilePreviewMaxBytes())
	}
	c.UI.FilePreviewMaxKB = 1
	if c.FilePreviewMaxKBResolved() != 64 {
		t.Fatalf("min clamp: %d", c.FilePreviewMaxKBResolved())
	}
	c.UI.FilePreviewMaxKB = 999999
	if c.FilePreviewMaxKBResolved() != 16384 {
		t.Fatalf("max clamp: %d", c.FilePreviewMaxKBResolved())
	}
}

func TestParseHomeISPPatterns(t *testing.T) {
	got := ParseHomeISPPatterns("Example Home ISP, Mullvad\nBT")
	if len(got) != 3 {
		t.Fatalf("%v", got)
	}
	if len(ParseHomeISPPatterns("  , \n")) != 0 {
		t.Fatal("empty should be empty slice")
	}
}

func TestPersistUI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.json")
	raw := `{"vmName":"TestVM","vmDataDir":"` + strings.ReplaceAll(dir, `\`, `\\`) + `","ui":{"warnPublicIpBeforeLaunch":true},"keep":1}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	off := false
	c := &Config{UI: UIConfig{
		FilePreviewMaxKB:         1024,
		HideRoutineNoise:         &off,
		WarnPublicIPBeforeLaunch: &off,
		HomeISPPatterns:          []string{"Virgin Media"},
	}}
	if err := c.PersistUI(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.UI.FilePreviewMaxKB != 1024 {
		t.Fatalf("preview=%d", loaded.UI.FilePreviewMaxKB)
	}
	if loaded.HideRoutineNoiseEnabled() {
		t.Fatal("hide noise should be false")
	}
	if loaded.WarnPublicIPBeforeLaunchEnabled() {
		t.Fatal("warn IP should be false")
	}
	if !loaded.IsHomeISP("Virgin Media") {
		t.Fatal("expected Virgin Media")
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(onDisk), `"keep"`) {
		t.Fatalf("persist must keep unrelated keys: %s", onDisk)
	}
}

func TestIsHomeISP(t *testing.T) {
	var nilCfg *Config
	if nilCfg.IsHomeISP("AS123 Example Home ISP Limited") {
		t.Fatal("default should not treat any ISP as home")
	}
	if nilCfg.IsHomeISP("Mullvad VPN") {
		t.Fatal("default should not treat other providers as home")
	}

	empty := &Config{UI: UIConfig{HomeISPPatterns: []string{}}}
	if empty.IsHomeISP("Example Home ISP") {
		t.Fatal("empty homeIspPatterns should match nothing")
	}

	custom := &Config{UI: UIConfig{HomeISPPatterns: []string{"Virgin Media", "BT"}}}
	if !custom.IsHomeISP("Virgin Media") {
		t.Fatal("expected Virgin Media match")
	}
	if custom.IsHomeISP("Example Home ISP") {
		t.Fatal("unlisted ISP should not match a custom list")
	}
}

func TestResolveSnapshotName(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{
		VMName:        "TestVM",
		CleanSnapshot: "Clean",
		Manifest: ManifestConfig{
			LogDir:                  dir,
			SessionBaselineSnapshot: "CleanSession",
		},
	}
	_ = os.WriteFile(filepath.Join(dir, "Evidence-hostfile.json"), []byte("{}"), 0o644)
	got := cfg.ResolveSnapshotName("hostfile")
	if got != "Evidence-hostfile" {
		t.Fatalf("got %q want Evidence-hostfile", got)
	}
}

func TestDefaultTransportAndClipboard(t *testing.T) {
	t.Cleanup(func() { GuestAdditionsCLI = false })
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.json")
	raw := `{
		"vmName": "TestVM",
		"vmDataDir": "` + strings.ReplaceAll(dir, `\`, `\\`) + `"
	}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EffectiveTransport() != TransportAgent {
		t.Fatalf("transport=%q", cfg.EffectiveTransport())
	}
	if cfg.Isolation.ClipboardMode != "disabled" {
		t.Fatalf("clipboardMode=%q", cfg.Isolation.ClipboardMode)
	}
	GuestAdditionsCLI = true
	if cfg.EffectiveTransport() != TransportGuestControl {
		t.Fatal("CLI flag should force guestcontrol")
	}
	GuestAdditionsCLI = false
	cfg.Guest.Transport = TransportGuestControl
	if cfg.EffectiveTransport() != TransportGuestControl {
		t.Fatal("config guestcontrol")
	}
}
