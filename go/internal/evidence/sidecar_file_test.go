package evidence

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/quarantine-lab/quarantine/internal/config"
)

func TestFileSidecarSize(t *testing.T) {
	if FileSidecarSize(nil) != 0 {
		t.Fatal("nil")
	}
	if n := FileSidecarSize(map[string]any{"s": float64(791266)}); n != 791266 {
		t.Fatalf("s float64: %d", n)
	}
	if n := FileSidecarSize(map[string]any{"size": int64(12)}); n != 12 {
		t.Fatalf("size int64: %d", n)
	}
}

func TestFileSidecarContentBase64(t *testing.T) {
	raw := []byte{'P', 0, 'e', 0}
	got, ok := FileSidecarContent(map[string]any{
		"c": "base64",
		"d": base64.StdEncoding.EncodeToString(raw),
	})
	if !ok {
		t.Fatal("expected content")
	}
	if string(got) != string(raw) {
		t.Fatalf("got %q", got)
	}
	if _, ok := FileSidecarContent(map[string]any{"c": "too_large", "s": float64(791266)}); ok {
		t.Fatal("too_large should not return bytes")
	}
}

func TestFileSidecarBeforeContent(t *testing.T) {
	entry := map[string]any{}
	AttachSidecarBeforeContent(entry, []byte(`{"filter_list":[]}`))
	got, ok := FileSidecarBeforeContent(entry)
	if !ok || string(got) != `{"filter_list":[]}` {
		t.Fatalf("got %#v ok=%v entry=%#v", got, ok, entry)
	}
	if _, ok := FileSidecarContent(entry); ok {
		t.Fatal("before payload must not satisfy FileSidecarContent")
	}
}

func TestFileSidecarIndex(t *testing.T) {
	dir := t.TempDir()
	path := `C:\payload\note.txt`
	doc := map[string]any{
		"files": []any{
			map[string]any{"p": path, "c": "text", "d": "hello"},
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	name := "Evidence-test"
	if err := os.WriteFile(filepath.Join(dir, name+"-changed-files.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	s := &Service{Cfg: &config.Config{Manifest: config.ManifestConfig{LogDir: dir}}}
	idx := s.FileSidecarIndex(name)
	entry, ok := FileSidecarLookup(idx, path)
	if !ok {
		t.Fatal("lookup")
	}
	data, ok := FileSidecarContent(entry)
	if !ok || string(data) != "hello" {
		t.Fatalf("content=%q ok=%v", data, ok)
	}
}
