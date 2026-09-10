package config

import (
	"os"
	"path/filepath"
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

func TestSafeSnapshotFileName(t *testing.T) {
	got := SafeSnapshotFileName(`Evidence/hostfile`)
	if got != "Evidence_hostfile" {
		t.Fatalf("got %q", got)
	}
}

func TestNormalizeTrafficMode(t *testing.T) {
	got, err := NormalizeTrafficMode("")
	if err != nil || got != "permissive" {
		t.Fatalf("empty: got %q %v", got, err)
	}
	got, err = NormalizeTrafficMode("FakeNet")
	if err != nil || got != "fakenet" {
		t.Fatalf("fakenet: got %q %v", got, err)
	}
	if _, err := NormalizeTrafficMode("nope"); err == nil {
		t.Fatal("expected error")
	}
}

func TestIsHomeISP(t *testing.T) {
	var nilCfg *Config
	if !nilCfg.IsHomeISP("AS123 Community Fibre Limited") {
		t.Fatal("default should treat Community Fibre as home")
	}
	if nilCfg.IsHomeISP("Mullvad VPN") {
		t.Fatal("default should not treat other providers as home")
	}

	empty := &Config{UI: UIConfig{HomeISPPatterns: []string{}}}
	if empty.IsHomeISP("Community Fibre") {
		t.Fatal("empty homeIspPatterns should match nothing")
	}

	custom := &Config{UI: UIConfig{HomeISPPatterns: []string{"Virgin Media", "BT"}}}
	if !custom.IsHomeISP("Virgin Media") {
		t.Fatal("expected Virgin Media match")
	}
	if custom.IsHomeISP("Community Fibre") {
		t.Fatal("Community Fibre should not match a custom list without it")
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
