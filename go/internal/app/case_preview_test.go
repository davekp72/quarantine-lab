package app

import (
	"strings"
	"testing"

	"github.com/quarantine-lab/quarantine/internal/cases"
	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/diff"
	"github.com/quarantine-lab/quarantine/internal/disk"
)

func TestPreviewAPIsUseCaseBodiesWithoutFlatten(t *testing.T) {
	logDir := t.TempDir()
	cfg := &config.Config{
		Manifest: config.ManifestConfig{LogDir: logDir},
		UI:       config.UIConfig{FilePreviewMaxKB: 512},
	}
	store := cases.NewStore(cfg)
	guest := `C:\payload\note.txt`
	meta, err := store.Save(cases.SaveRequest{
		Result: &diff.Result{
			Meta: diff.MetaSection{FromSnapshot: "CleanSession", ToSnapshot: "Evidence-gone"},
			Files: diff.FilesSection{
				Modified: []diff.FileModified{{Path: guest, After: diff.FileDetail{Path: guest, Size: 7}}},
			},
		},
		ExcludeNoise: false,
		MaxBodyBytes: 4096,
		LoadFrom:     func(string) cases.Body { return cases.Body{Data: []byte("from-archived")} },
		LoadTo:       func(string) cases.Body { return cases.Body{Data: []byte("to-archived")} },
	})
	if err != nil {
		t.Fatal(err)
	}

	a := &App{
		Cfg:        cfg,
		Cases:      store,
		ActiveCase: meta.ID,
		Disk:       &disk.Reader{},
	}

	res, err := a.ReadSnapshotFileWails("DeletedSnap", guest)
	if err != nil {
		t.Fatal(err)
	}
	if res["source"] != "case" {
		t.Fatalf("source=%v", res["source"])
	}
	content, _ := res["content"].(string)
	if !strings.Contains(content, "to-archived") {
		t.Fatalf("content=%q", content)
	}

	diffRes, err := a.DiffSnapshotFileWails("DeletedFrom", "DeletedTo", guest)
	if err != nil {
		t.Fatal(err)
	}
	if diffRes["fromSource"] != "case" || diffRes["toSource"] != "case" {
		t.Fatalf("%v", diffRes)
	}
	from, _ := diffRes["fromContent"].(string)
	to, _ := diffRes["toContent"].(string)
	if !strings.Contains(from, "from-archived") || !strings.Contains(to, "to-archived") {
		t.Fatalf("from=%q to=%q", from, to)
	}
}

func TestListCasesWailsRoundTrip(t *testing.T) {
	logDir := t.TempDir()
	cfg := &config.Config{Manifest: config.ManifestConfig{LogDir: logDir}}
	a := &App{Cfg: cfg, Cases: cases.NewStore(cfg)}
	meta, err := a.Cases.Save(cases.SaveRequest{
		Result: &diff.Result{
			Meta:  diff.MetaSection{FromSnapshot: "CleanSession", ToSnapshot: "Evidence-x"},
			Files: diff.FilesSection{Added: []diff.FileDetail{{Path: `C:\payload\a.exe`, Size: 1}}},
		},
		LoadTo: func(string) cases.Body { return cases.Body{Data: []byte("x")} },
	})
	if err != nil {
		t.Fatal(err)
	}
	list, err := a.ListCasesWails()
	if err != nil || len(list) != 1 {
		t.Fatalf("list=%v err=%v", list, err)
	}
	loaded, err := a.LoadCaseWails(meta.ID)
	if err != nil {
		t.Fatal(err)
	}
	if a.ActiveCase != meta.ID {
		t.Fatalf("active=%q", a.ActiveCase)
	}
	if loaded["compareJSON"] == "" {
		t.Fatal("missing compare json")
	}
	a.ClearActiveCaseWails()
	if a.ActiveCase != "" {
		t.Fatal("active case should clear")
	}
}

func TestSaveCaseWailsRequiresCompare(t *testing.T) {
	logDir := t.TempDir()
	cfg := &config.Config{Manifest: config.ManifestConfig{LogDir: logDir}}
	a := &App{Cfg: cfg, Cases: cases.NewStore(cfg)}
	if _, err := a.SaveCaseWails(true); err == nil {
		t.Fatal("expected error without compare")
	}
	a.LastResult = &diff.Result{
		Meta:  diff.MetaSection{FromSnapshot: "CleanSession", ToSnapshot: "Evidence-x"},
		Files: diff.FilesSection{Added: []diff.FileDetail{{Path: `C:\payload\a.exe`, Size: 1}}},
	}
	res, err := a.SaveCaseWails(true)
	if err != nil {
		t.Fatal(err)
	}
	if res["id"] == "" {
		t.Fatal("missing id")
	}
	a.ActiveCase = res["id"].(string)
	if _, err := a.SaveCaseWails(true); err == nil {
		t.Fatal("expected error while reviewing a case")
	}
}
