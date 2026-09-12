package vbox

import (
	"fmt"
	"strings"
	"testing"
)

func TestSnapshotTreeParse(t *testing.T) {
	out := strings.Join([]string{
		`SnapshotName="Clean"`,
		`SnapshotUUID="70c05276-413c-45d3-9c66-25c1dabb8438"`,
		`SnapshotDescription="Known-good baseline for quarantine reset."`,
		`SnapshotName-1="CleanSession"`,
		`SnapshotUUID-1="abd48eef-78ea-4463-a704-ef4e7c2d7106"`,
		`SnapshotDescription-1="Known-good baseline for quarantine reset."`,
		`SnapshotName-1-1="Evidence-hostfile"`,
		`SnapshotUUID-1-1="7408f1b6-ff10-4517-833f-d22744ffba8a"`,
		`SnapshotDescription-1-1="Preserved session state."`,
	}, "\n")

	tree := parseSnapshotTree(out)
	if len(tree) != 3 {
		t.Fatalf("expected 3 snapshots, got %d", len(tree))
	}
	if tree[2].Name != "Evidence-hostfile" {
		t.Fatalf("missing nested snap: %#v", tree[2])
	}

	desc := DescendantUUIDs(tree[1].UUID, tree)
	if len(desc) != 1 || desc[0] != tree[2].UUID {
		t.Fatalf("expected one descendant, got %#v", desc)
	}
	if len(DescendantUUIDs(tree[2].UUID, tree)) != 0 {
		t.Fatal("leaf should have no descendants")
	}
}

func TestIsNoSnapshotsError(t *testing.T) {
	err := fmt.Errorf("VBoxManage snapshot Quarantine-Win11 list --machinereadable: exit status 1: This machine does not have any snapshots")
	if !isNoSnapshotsError(err) {
		t.Fatal("expected empty snapshot list to be ignored")
	}
	if isNoSnapshotsError(fmt.Errorf("VBoxManage snapshot foo take: exit status 1: NS_ERROR_FAILURE")) {
		t.Fatal("real snapshot errors must not be ignored")
	}
	if isNoSnapshotsError(nil) {
		t.Fatal("nil is not a no-snapshots error")
	}
}

func TestNewClientMissing(t *testing.T) {
	c, err := NewClient("")
	if err != nil {
		if !strings.Contains(err.Error(), "VBoxManage") {
			t.Fatalf("unexpected: %v", err)
		}
		return
	}
	if c.Binary == "" {
		t.Fatal("expected binary path")
	}
}
