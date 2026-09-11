package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quarantine-lab/quarantine/internal/config"
)

func TestLoadDiffFileRestrictsToEvidenceDirs(t *testing.T) {
	root := t.TempDir()
	manifestDir := filepath.Join(root, "manifests")
	if err := os.MkdirAll(manifestDir, 0o755); err != nil {
		t.Fatal(err)
	}
	okPath := filepath.Join(manifestDir, "diff-a-vs-b.diff.json")
	payload := `{"meta":{"fromSnapshot":"a"},"summary":{}}`
	if err := os.WriteFile(okPath, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}

	outside := filepath.Join(root, "secrets.txt")
	if err := os.WriteFile(outside, []byte("host-secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	a := &App{Cfg: &config.Config{
		VMDataDir: root,
		Manifest:  config.ManifestConfig{LogDir: manifestDir},
	}}

	got, err := a.LoadDiffFile(okPath)
	if err != nil {
		t.Fatalf("allowed path: %v", err)
	}
	if got != payload {
		t.Fatalf("content mismatch: %q", got)
	}

	_, err = a.LoadDiffFile(outside)
	if err == nil {
		t.Fatal("expected denial for path outside evidence dirs")
	}
	if !strings.Contains(err.Error(), "evidence") && !strings.Contains(err.Error(), "lab") {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = a.LoadDiffFile(filepath.Join(manifestDir, "..", "secrets.txt"))
	if err == nil {
		t.Fatal("expected denial for path traversal")
	}
}

func TestLoadDiffFileEmptyUsesLastDiffPath(t *testing.T) {
	root := t.TempDir()
	manifestDir := filepath.Join(root, "manifests")
	_ = os.MkdirAll(manifestDir, 0o755)
	okPath := filepath.Join(manifestDir, "last.diff.json")
	if err := os.WriteFile(okPath, []byte(`{"ok":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	a := &App{
		Cfg: &config.Config{
			VMDataDir: root,
			Manifest:  config.ManifestConfig{LogDir: manifestDir},
		},
		LastDiffPath: okPath,
	}
	got, err := a.LoadDiffFile("")
	if err != nil {
		t.Fatal(err)
	}
	if got != `{"ok":true}` {
		t.Fatalf("got %q", got)
	}
}
