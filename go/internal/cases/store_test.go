package cases

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quarantine-lab/quarantine/internal/diff"
)

func TestSaveListLoadDeleteRoundTrip(t *testing.T) {
	root := t.TempDir()
	store := &Store{Root: root}
	netDir := filepath.Join(t.TempDir(), "Evidence-test-network")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(netDir, "capture.pcap"), []byte("pcap"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(netDir, "flows.jsonl"), []byte(`{"host":"evil.test"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	fromBody := []byte("from-note")
	toBody := []byte("to-note")
	req := SaveRequest{
		Result:       sampleResult(),
		ExcludeNoise: true,
		ToNetworkDir: netDir,
		MaxBodyBytes: 4096,
		LoadFrom:     func(string) Body { return Body{Data: fromBody} },
		LoadTo:       func(string) Body { return Body{Data: toBody} },
	}
	meta, err := store.Save(req)
	if err != nil {
		t.Fatal(err)
	}
	if meta.ID == "" || !meta.ExcludeNoise || !meta.NetworkCopied {
		t.Fatalf("%+v", meta)
	}
	if meta.FileBodies < 2 {
		t.Fatalf("expected from+to bodies, got %d", meta.FileBodies)
	}

	list, err := store.List()
	if err != nil || len(list) != 1 || list[0].ID != meta.ID {
		t.Fatalf("list=%v err=%v", list, err)
	}

	raw, got, err := store.LoadCompare(meta.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != meta.ID {
		t.Fatalf("meta id %s", got.ID)
	}
	var archived diff.Result
	if err := json.Unmarshal(raw, &archived); err != nil {
		t.Fatal(err)
	}
	if archived.Summary.FilesAdded != 1 {
		t.Fatalf("archived added=%d (noise should be gone)", archived.Summary.FilesAdded)
	}
	if len(archived.Network.Requests) != 1 {
		t.Fatalf("http rows=%d", len(archived.Network.Requests))
	}
	ff, _ := archived.Network.Requests[0]["flowFile"].(string)
	if !strings.Contains(filepath.ToSlash(ff), "/network/flows.jsonl") {
		t.Fatalf("flowFile not rewritten: %q", ff)
	}
	if _, err := os.Stat(filepath.Join(store.NetworkDir(meta.ID), "capture.pcap")); err != nil {
		t.Fatal(err)
	}

	from, to, _, err := store.ReadBodies(meta.ID, `C:\payload\note.txt`)
	if err != nil {
		t.Fatal(err)
	}
	if string(from) != "from-note" || string(to) != "to-note" {
		t.Fatalf("from=%q to=%q", from, to)
	}

	if err := store.Delete(meta.ID); err != nil {
		t.Fatal(err)
	}
	list, err = store.List()
	if err != nil || len(list) != 0 {
		t.Fatalf("after delete list=%v err=%v", list, err)
	}
}

func TestSaveNoiseOffKeepsRoutineRows(t *testing.T) {
	store := &Store{Root: t.TempDir()}
	on, err := store.Save(SaveRequest{Result: sampleResult(), ExcludeNoise: true, MaxBodyBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	off, err := store.Save(SaveRequest{Result: sampleResult(), ExcludeNoise: false, MaxBodyBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	onRaw, _, err := store.LoadCompare(on.ID)
	if err != nil {
		t.Fatal(err)
	}
	offRaw, _, err := store.LoadCompare(off.ID)
	if err != nil {
		t.Fatal(err)
	}
	var onR, offR diff.Result
	if err := json.Unmarshal(onRaw, &onR); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(offRaw, &offR); err != nil {
		t.Fatal(err)
	}
	if onR.Summary.FilesAdded >= offR.Summary.FilesAdded {
		t.Fatalf("noise-on added=%d noise-off added=%d", onR.Summary.FilesAdded, offR.Summary.FilesAdded)
	}
	if offR.Summary.FilesAdded != 2 {
		t.Fatalf("noise-off should keep temp file: %d", offR.Summary.FilesAdded)
	}
}

func sampleResult() *diff.Result {
	return &diff.Result{
		Meta: diff.MetaSection{FromSnapshot: "CleanSession", ToSnapshot: "Evidence-test"},
		Files: diff.FilesSection{
			Added: []diff.FileDetail{
				{Path: `C:\payload\drop.exe`, Size: 100, Hash: "aa"},
				{Path: `C:\Windows\Temp\foo.txt`, Size: 4},
			},
			Modified: []diff.FileModified{
				{Path: `C:\payload\note.txt`, After: diff.FileDetail{Path: `C:\payload\note.txt`, Size: 8}},
			},
		},
		Network: &diff.NetworkSection{
			Requests: []map[string]any{
				{"host": "evil.test", "flowFile": `Z:\logs\Evidence-test-network\flows.jsonl`},
				{"host": "microsoft.com", "flowFile": `Z:\logs\Evidence-test-network\flows.jsonl`},
			},
			DNS: []map[string]any{
				{"query": "evil.test"},
				{"query": "microsoft.com"},
			},
		},
	}
}
