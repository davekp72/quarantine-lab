package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/evidence"
)

func TestReadSnapshotFileSkipsDiskWhenSidecarTooLarge(t *testing.T) {
	dir := t.TempDir()
	path := `C:\Windows\System32\PerfStringBackup.INI`
	sidecar := map[string]any{
		"files": []any{
			map[string]any{
				"p":      path,
				"s":      float64(791266),
				"h":      "abc",
				"change": "added",
			},
		},
	}
	raw, err := json.Marshal(sidecar)
	if err != nil {
		t.Fatal(err)
	}
	name := "Evidence-test"
	if err := os.WriteFile(filepath.Join(dir, name+"-changed-files.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	a := &App{
		Evidence: &evidence.Service{Cfg: &config.Config{
			Manifest: config.ManifestConfig{LogDir: dir},
		}},
	}
	res, err := a.ReadSnapshotFile(name, path)
	if err != nil {
		t.Fatal(err)
	}
	if res["reason"] != "too_large" {
		t.Fatalf("reason=%v content=%v", res["reason"], res["content"])
	}
	if res["unavailable"] != true {
		t.Fatalf("expected unavailable: %v", res)
	}
	msg, _ := res["content"].(string)
	if !strings.Contains(msg, "772.7 KiB") && !strings.Contains(msg, "791266") {
		t.Fatalf("missing size in %q", msg)
	}

	a.Cfg = &config.Config{UI: config.UIConfig{FilePreviewMaxKB: 1024}}
	res, err = a.ReadSnapshotFile(name, path)
	if err == nil {
		t.Fatal("expected disk-unavailable once size is under the raised limit")
	}
	if !strings.Contains(err.Error(), "disk reader unavailable") {
		t.Fatalf("got %v", err)
	}
}

func TestDecodePreviewBytesUTF16LE(t *testing.T) {
	// BOM + "Hi"
	data := []byte{0xFF, 0xFE, 'H', 0, 'i', 0}
	if got := decodePreviewBytes(data); got != "Hi" {
		t.Fatalf("BOM: %q", got)
	}
	noBOM := []byte{'H', 0, 'i', 0, '!', 0, '\n', 0}
	if got := decodePreviewBytes(noBOM); got != "Hi!\n" {
		t.Fatalf("no BOM: %q", got)
	}
}

func TestFileTreeFromDiffIncludesSize(t *testing.T) {
	a := &App{}
	raw := `{
		"files": {
			"added": [{"path": "C:\\\\Windows\\\\System32\\\\PerfStringBackup.INI", "size": 791266}]
		}
	}`
	tree, err := a.FileTreeFromDiff(raw)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := tree.(map[string]any)
	node := findTreeNode(root, "PerfStringBackup.INI")
	if node == nil {
		t.Fatal("leaf not found")
	}
	size, _ := node["size"].(int64)
	if size != 791266 {
		t.Fatalf("size=%v (%T)", node["size"], node["size"])
	}
}

func TestSetUISettingsPersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(path, []byte(`{"vmName":"TestVM","vmDataDir":"`+strings.ReplaceAll(dir, `\`, `\\`)+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	a := &App{ConfigPath: path, Cfg: &config.Config{}}
	res, err := a.SetUISettingsWails(1024, false, false, false, "Virgin Media")
	if err != nil {
		t.Fatal(err)
	}
	if res["filePreviewMaxKb"] != 1024 {
		t.Fatalf("%v", res)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.FilePreviewMaxKBResolved() != 1024 {
		t.Fatalf("disk preview=%d", loaded.FilePreviewMaxKBResolved())
	}
	if loaded.HideRoutineNoiseEnabled() || loaded.RefreshOnCompareEnabled() || loaded.WarnPublicIPBeforeLaunchEnabled() {
		t.Fatalf("bools not saved: %#v", loaded.UI)
	}
}

func findTreeNode(node map[string]any, name string) map[string]any {
	if node == nil {
		return nil
	}
	if node["name"] == name {
		return node
	}
	children, _ := node["children"].(map[string]any)
	for _, child := range children {
		m, _ := child.(map[string]any)
		if found := findTreeNode(m, name); found != nil {
			return found
		}
	}
	return nil
}
