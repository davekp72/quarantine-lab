package diff

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func TestCompareEventsBaselineUsesChangeField(t *testing.T) {
	left := &evidence.Manifest{Snapshot: "CleanSession", ScanMode: "events", Files: nil}
	right := &evidence.Manifest{
		Snapshot: "Evidence-test",
		ScanMode: "events",
		Files: []evidence.FileEntry{
			{P: `C:\Windows\System32\dodge.txt`, Change: "added"},
			{P: `C:\Windows\System32\drivers\etc\hosts`, Change: "modified"},
			{P: `C:\Windows\System32\gone.dll`, Change: "removed"},
			{P: `C:\Users\jkcooper\AppData\Local\Temp\noise.txt`, Change: "added"},
		},
	}
	res, err := Compare("l.json", "r.json", left, right)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files.Added) != 1 || !strings.Contains(res.Files.Added[0].Path, "dodge.txt") {
		t.Fatalf("added=%+v", res.Files.Added)
	}
	if len(res.Files.Modified) != 1 || !strings.Contains(res.Files.Modified[0].Path, "hosts") {
		t.Fatalf("modified=%+v", res.Files.Modified)
	}
	if len(res.Files.Removed) != 1 || !strings.Contains(res.Files.Removed[0].Path, "gone.dll") {
		t.Fatalf("removed=%+v", res.Files.Removed)
	}
}

func TestCompareEventsRelabelsPresentRemovedAndDropsDeletedNoise(t *testing.T) {
	left := &evidence.Manifest{Snapshot: "CleanSession", ScanMode: "events", Files: nil}
	right := &evidence.Manifest{
		Snapshot: "Evidence-test",
		ScanMode: "events",
		Files: []evidence.FileEntry{
			{P: `C:\Windows\System32\dodge.txt`, Change: "removed", H: "abc", S: 28, C: "text", Src: "usn+sysmon"},
			{P: `C:\$Extend\$Deleted\00020000000408F673F5ACE4`, Change: "removed"},
			{P: `C:\Windows\SystemTemp\__PSScriptPolicyTest_x.ps1`, Change: "removed"},
			{P: `C:\Windows\ServiceState\WinHttpAutoProxySvc\Data\1.cache`, Change: "removed"},
			{P: `C:\Windows\SystemTemp\50ylbunx\50ylbunx.dll`, Change: "removed"},
		},
	}
	res, err := Compare("l.json", "r.json", left, right)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files.Added) != 1 || !strings.Contains(res.Files.Added[0].Path, "dodge.txt") {
		t.Fatalf("added=%+v", res.Files.Added)
	}
	if len(res.Files.Removed) != 0 {
		t.Fatalf("deleted noise still present: %+v", res.Files.Removed)
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
