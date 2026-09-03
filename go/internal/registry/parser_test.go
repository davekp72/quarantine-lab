package registry

import (
	"testing"

	"github.com/quarantine-lab/quarantine/internal/evidence"
)

func TestFriendlySIDLabel(t *testing.T) {
	names := map[string]string{
		"S-1-5-21-2173276180-4090869881-14400703-1003": "jkcooper",
	}
	got := FriendlySIDLabel("S-1-5-21-2173276180-4090869881-14400703-1003", names)
	if got != "jkcooper" {
		t.Fatalf("got %q", got)
	}
	if FriendlySIDLabel("S-1-5-18", nil) != "SYSTEM" {
		t.Fatalf("expected SYSTEM")
	}
}

func TestBuildTreeSIDLabel(t *testing.T) {
	entries := []evidence.RegistryEntry{
		{K: `HKU:\S-1-5-21-1-2-3-1003\Software\Test`, N: "Foo", V: "1", T: "REG_SZ"},
	}
	tree := BuildTree(entries, map[string]string{
		"S-1-5-21-1-2-3-1003": "jkcooper",
	})
	hku := tree.Children["HKU:"]
	if hku == nil {
		t.Fatal("missing HKU:")
	}
	sid := hku.Children["S-1-5-21-1-2-3-1003"]
	if sid == nil {
		t.Fatal("missing SID child")
	}
	if sid.Label != "jkcooper" {
		t.Fatalf("label=%q want jkcooper", sid.Label)
	}
	if sid.Name != "S-1-5-21-1-2-3-1003" {
		t.Fatalf("name should remain SID, got %q", sid.Name)
	}
}

func TestBuildChangedTree(t *testing.T) {
	tree := BuildChangedTree([]ChangedEntry{
		{Key: `HKCU\Software\A`, Name: "X", Value: "1", Change: "added"},
		{Key: `HKCU\Software\B`, Name: "Y", Value: "2", Change: "removed"},
		{Key: `HKCU\Software\C`, Name: "Z", Before: "old", After: "new", Change: "modified"},
	}, nil)
	soft := tree.Children["HKCU"].Children["Software"]
	if soft.Children["A"].Change != "added" {
		t.Fatalf("A change=%q", soft.Children["A"].Change)
	}
	if soft.Children["B"].Change != "removed" {
		t.Fatalf("B change=%q", soft.Children["B"].Change)
	}
	if soft.Children["C"].Change != "modified" {
		t.Fatalf("C change=%q", soft.Children["C"].Change)
	}
	if soft.Change != "modified" {
		t.Fatalf("parent with mixed children should be modified, got %q", soft.Change)
	}
}
