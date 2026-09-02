package diff

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/quarantine-lab/quarantine/internal/evidence"
)

func TestCompareMinimal(t *testing.T) {
	left := &evidence.Manifest{
		Snapshot: "CleanSession",
		Files:    []evidence.FileEntry{{P: `C:\a.txt`, H: "1"}},
		Registry: []evidence.RegistryEntry{{K: `HKLM\Software`, N: "x", V: "1"}},
	}
	right := &evidence.Manifest{
		Snapshot: "Evidence-test",
		Files: []evidence.FileEntry{
			{P: `C:\a.txt`, H: "1"},
			{P: `C:\b.txt`, H: "2"},
		},
		Registry: []evidence.RegistryEntry{
			{K: `HKLM\Software`, N: "x", V: "2"},
			{K: `HKLM\New`, N: "y", V: "1"},
		},
	}
	res, err := Compare("left.json", "right.json", left, right)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files.Added) != 1 || res.Files.Added[0].Path != `C:\b.txt` {
		t.Fatalf("added files: %+v", res.Files.Added)
	}
	if len(res.Registry.Modified) != 1 {
		t.Fatalf("modified reg: %+v", res.Registry.Modified)
	}
	if len(res.Registry.Added) != 1 {
		t.Fatalf("added reg: %+v", res.Registry.Added)
	}
}

func TestGoldenDiffIfPresent(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	diffPath := filepath.Join(root, "..", "D:", "Vbox", "LabVM", "logs", "manifests", "diff-CleanSession-vs-Evidence-hostfile.diff.json")
	// Also try relative from workspace manifests if synced
	alt := filepath.Join(root, "logs", "manifests", "diff-CleanSession-vs-Evidence-hostfile.diff.json")
	path := diffPath
	if _, err := os.Stat(path); err != nil {
		path = alt
	}
	if _, err := os.Stat(path); err != nil {
		t.Skip("golden diff not available")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var golden map[string]any
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	summary, _ := golden["summary"].(map[string]any)
	if summary == nil {
		t.Fatal("missing summary")
	}
	// Sanity: golden file has expected top-level keys
	for _, key := range []string{"meta", "files", "registry"} {
		if _, ok := golden[key]; !ok {
			t.Fatalf("golden missing %s", key)
		}
	}
}
