package smoke

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/diff"
	"github.com/quarantine-lab/quarantine/internal/evidence"
)

func repoConfigPath(t *testing.T) string {
	t.Helper()
	candidates := []string{
		filepath.Join("..", "..", "..", "config", "quarantine-vm.json"),
		filepath.Join("config", "quarantine-vm.json"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	t.Skip("quarantine-vm.json not found")
	return ""
}

func TestConfigLoads(t *testing.T) {
	path := repoConfigPath(t)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VMName == "" {
		t.Fatal("vmName empty")
	}
}

func TestEvidencePaths(t *testing.T) {
	path := repoConfigPath(t)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	logDir := cfg.ManifestLogDir()
	if _, err := os.Stat(logDir); err != nil {
		t.Skip("manifest log dir not present")
	}
}

func TestDiffEngineRoundTrip(t *testing.T) {
	left := &evidence.Manifest{Snapshot: "A", Files: []evidence.FileEntry{{P: `C:\x`, H: "1"}}}
	right := &evidence.Manifest{Snapshot: "B", Files: []evidence.FileEntry{{P: `C:\x`, H: "2"}}}
	res, err := diff.Compare("a.json", "b.json", left, right)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files.Modified) != 1 {
		t.Fatalf("expected 1 modified file, got %d", len(res.Files.Modified))
	}
}
