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
