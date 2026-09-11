package collectors

import (
	"encoding/json"
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
	raw, n, err := ChangedFiles(usn, sysmon, 1, 64)
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
	if strings.Contains(s, `noise.txt`) {
		t.Fatalf("temp noise should be filtered: %s", s)
	}
	if strings.Contains(s, `HKLM\Software\Run`) {
		t.Fatalf("registry event must not be a file: %s", s)
	}
}
