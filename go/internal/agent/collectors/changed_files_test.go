package collectors

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChangedFilesKeepsSystem32DropsCache(t *testing.T) {
	usn, _ := json.Marshal(map[string]any{
		"events": []any{
			map[string]any{"path": `C:\Windows\System32\drivers\etc\hosts`, "change": "modified", "fileName": "hosts"},
			map[string]any{"path": `C:\Windows\System32\dodge.txt`, "change": "added", "fileName": "dodge.txt"},
		},
	})
	sysmon, _ := json.Marshal(map[string]any{
		"events": []any{
			map[string]any{"eid": float64(11), "t": "FileCreate", "target": `C:\Windows\System32\dodge.txt`},
			map[string]any{"eid": float64(11), "t": "FileCreate", "target": `C:\Users\analyst\AppData\Local\Temp\noise.txt`},
			map[string]any{"eid": float64(12), "t": "RegistryEvent", "target": `HKLM\Software\Run`},
		},
	})
	raw, n, err := ChangedFiles(usn, sysmon, 1, 64, 32)
	if err != nil {
		t.Fatal(err)
	}
	if n < 2 {
		t.Fatalf("fileCount=%d payload=%s", n, raw)
	}
	s := string(raw)
	if !strings.Contains(s, `dodge.txt`) {
		t.Fatalf("missing dodge.txt: %s", s)
	}
	if !strings.Contains(s, `hosts`) {
		t.Fatalf("missing hosts: %s", s)
	}
	// Temp paths stay in the list (tagged noise) so the UI toggle can change counts.
	if !strings.Contains(s, `noise.txt`) || !strings.Contains(s, `"noise"`) {
		t.Fatalf("expected noise-tagged temp file: %s", s)
	}
	if strings.Contains(s, `HKLM\Software\Run`) {
		t.Fatalf("registry event must not be a file: %s", s)
	}
}

func TestChangedFilesEmbedsDesktopContent(t *testing.T) {
	// Must not live under %TEMP% — that path is classified as noise.
	desktop := filepath.Join(`C:\Users\Public`, "Desktop", "QuarantineLabPreviewTest")
	if err := os.MkdirAll(desktop, 0o755); err != nil {
		t.Skip("cannot create Public Desktop test dir: ", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(desktop) })
	marker := filepath.Join(desktop, "marker.txt")
	body := "QuarantineLabTest marker\n"
	if err := os.WriteFile(marker, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	usn, _ := json.Marshal(map[string]any{
		"events": []any{
			map[string]any{"path": marker, "change": "added", "fileName": "marker.txt"},
		},
	})
	raw, n, err := ChangedFiles(usn, nil, 50, 256, 32)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("n=%d %s", n, raw)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	files, _ := out["files"].([]any)
	entry, _ := files[0].(map[string]any)
	if entry["c"] != "text" {
		t.Fatalf("expected embedded text content, got %#v", entry)
	}
	if entry["d"] != body {
		t.Fatalf("body=%v", entry["d"])
	}
}

func TestChangedFilesEmbedsLowPriorityAppData(t *testing.T) {
	dir := filepath.Join(`C:\Users\Public`, "QuarantineLabAppDataEmbed")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	// Public\... is priority 4 (not Desktop/Downloads), matching AppData-style paths.
	marker := filepath.Join(dir, "RecommendationsFilterList.json")
	body := `{"filter_list":[]}`
	if err := os.WriteFile(marker, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	usn, _ := json.Marshal(map[string]any{
		"events": []any{
			map[string]any{"path": marker, "change": "modified", "fileName": "RecommendationsFilterList.json"},
		},
	})
	raw, n, err := ChangedFiles(usn, nil, 50, 256, 32)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("n=%d %s", n, raw)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	entry, _ := out["files"].([]any)[0].(map[string]any)
	if entry["c"] != "text" || entry["d"] != body {
		t.Fatalf("expected low-priority embed, got %#v", entry)
	}
}
