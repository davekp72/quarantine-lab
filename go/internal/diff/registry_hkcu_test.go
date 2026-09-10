package diff

import (
	"testing"

	"github.com/quarantine-lab/quarantine/internal/evidence"
)

func TestSuppressFalseHKCURemovals(t *testing.T) {
	left := &evidence.Manifest{
		Snapshot: "CleanSession",
		Registry: []evidence.RegistryEntry{
			{K: `HKU:\S-1-5-21-1-2-3-1003\Software\A`, N: "x", V: "1"},
			{K: `HKU:\S-1-5-21-1-2-3-1003\Software\B`, N: "y", V: "2"},
		},
	}
	// Pad to satisfy the >=50 heuristic when warnings are absent.
	for i := 0; i < 60; i++ {
		left.Registry = append(left.Registry, evidence.RegistryEntry{
			K: `HKU:\S-1-5-21-1-2-3-1003\Software\Pad`, N: string(rune('a'+i%26)) + string(rune('0'+i/26)), V: i,
		})
	}
	right := &evidence.Manifest{
		Snapshot:         "Evidence",
		Registry:         []evidence.RegistryEntry{},
		UserRegistryWarn: []string{"WTSQueryUserToken: Access is denied."},
	}
	added, removed, modified, volatile := diffRegistry(left.Registry, right.Registry)
	if len(removed) < 50 {
		t.Fatalf("expected many raw removals, got %d", len(removed))
	}
	added, removed, modified, warns := suppressFalseHKCUDiff(left, right, added, removed, modified)
	_ = volatile
	if len(removed) != 0 {
		t.Fatalf("expected HKCU removals suppressed, got %d", len(removed))
	}
	if len(added) != 0 || len(modified) != 0 {
		t.Fatalf("unexpected leftover diffs")
	}
	if len(warns) == 0 {
		t.Fatal("expected warning")
	}
}
