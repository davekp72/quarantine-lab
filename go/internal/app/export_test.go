package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/quarantine-lab/quarantine/internal/cases"
	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/diff"
	"github.com/quarantine-lab/quarantine/internal/evidence"
)

func TestExportBaseName(t *testing.T) {
	if got := exportBaseName(`C:\Users\x\drop.exe`); got != "drop.exe" {
		t.Fatalf("got %q", got)
	}
	if got := exportBaseName(`evil:name?.dll`); got != "evil_name_.dll" {
		t.Fatalf("got %q", got)
	}
}

func TestLoadExportFileFromSidecar(t *testing.T) {
	dir := t.TempDir()
	guest := `C:\payload\note.txt`
	sidecar := map[string]any{
		"files": []any{
			map[string]any{"p": guest, "c": "text", "d": "hello-export", "s": 12},
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
		Cfg: &config.Config{},
		Evidence: &evidence.Service{Cfg: &config.Config{
			Manifest: config.ManifestConfig{LogDir: dir},
		}},
	}
	data, src, err := a.loadExportFile(name, guest)
	if err != nil {
		t.Fatal(err)
	}
	if src != "sidecar" || string(data) != "hello-export" {
		t.Fatalf("src=%s data=%q", src, data)
	}
}

func TestLoadExportFileFromCase(t *testing.T) {
	root := t.TempDir()
	store := &cases.Store{Root: root}
	guest := `C:\payload\note.txt`
	meta, err := store.Save(cases.SaveRequest{
		Result: &diff.Result{
			Meta:  diff.MetaSection{FromSnapshot: "CleanSession", ToSnapshot: "Evidence-test"},
			Files: diff.FilesSection{Added: []diff.FileDetail{{Path: guest, Size: 10}}},
		},
		LoadTo: func(string) cases.Body { return cases.Body{Data: []byte("case-bytes")} },
	})
	if err != nil {
		t.Fatal(err)
	}
	a := &App{Cases: store, ActiveCase: meta.ID}
	data, src, err := a.loadExportFile("ignored", guest)
	if err != nil {
		t.Fatal(err)
	}
	if src != "case" || string(data) != "case-bytes" {
		t.Fatalf("src=%s data=%q", src, data)
	}
}

func TestCopyRegularFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "capture.pcap")
	dest := filepath.Join(dir, "out.pcap")
	if err := os.WriteFile(src, []byte("pcap-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := copyRegularFile(src, dest); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != "pcap-bytes" {
		t.Fatalf("got %q err=%v", got, err)
	}
}
