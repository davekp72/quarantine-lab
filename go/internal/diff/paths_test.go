package diff

import (
	"testing"

	"github.com/quarantine-lab/quarantine/internal/evidence"
)

func TestIsUnresolvedUSNLeafPath(t *testing.T) {
	leaf := []string{
		`C:\hosts.tmp`,
		`C:\1297887161`,
		`C:\_usn_leaf\foo.tmp`,
		`c:\$RUCIQVE.txt`,
	}
	for _, p := range leaf {
		if !IsUnresolvedUSNLeafPath(p) {
			t.Fatalf("expected leaf: %q", p)
		}
	}
	real := []string{
		`C:\Users\Public\Quarantine\Install-QuarantineAgent.ps1`,
		`C:\Windows\SystemTemp\__PSScriptPolicyTest_ugmeaer1.thp.ps1`,
		`C:\`,
		``,
	}
	for _, p := range real {
		if IsUnresolvedUSNLeafPath(p) {
			t.Fatalf("expected real path: %q", p)
		}
	}
}

func TestCompareFiltersUSNLeafFiles(t *testing.T) {
	left := &evidence.Manifest{Snapshot: "CleanSession", ScanMode: "events"}
	right := &evidence.Manifest{
		Snapshot: "Evidence-test",
		ScanMode: "events",
		Files: []evidence.FileEntry{
			{P: `C:\randomleaf`, Change: "added", Src: "events"},
			{P: `C:\Users\Public\Quarantine\Install.ps1`, Change: "added", Src: "events"},
			{P: `C:\real.txt`, H: "abc", S: 12, Change: "added"},
		},
	}
	res, err := Compare("left.json", "right.json", left, right)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files.Added) != 2 {
		t.Fatalf("added files: %+v", res.Files.Added)
	}
	if res.Summary.FilesAdded != 2 {
		t.Fatalf("summary count: %d", res.Summary.FilesAdded)
	}
}
