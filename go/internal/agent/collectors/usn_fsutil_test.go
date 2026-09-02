//go:build windows

package collectors

import "testing"

func TestMapFsutilUsnRowNewFormat(t *testing.T) {
	colMap := fsutilCSVMap{usn: 4, timestamp: 5, reason: 6, fileName: 10}
	row := []string{
		"2", "0",
		"0x0000000000000000000D0000000A0CD9",
		"0x0000000000000000001200000019ab0e",
		"Data extend | File create | Close",
		"02/09/2026 19:45:38",
		"0x0000000016e93870",
		"0x00000000", "0x00000000", "0x00000020",
		"hosts",
	}
	ev := mapFsutilUsnRow(row, colMap)
	if ev == nil {
		t.Fatal("expected parsed event")
	}
	if ev["fileName"] != "hosts" {
		t.Fatalf("fileName=%v", ev["fileName"])
	}
	if ev["usn"] != "0x0000000016e93870" {
		t.Fatalf("usn=%v", ev["usn"])
	}
}

func TestMapFsutilUsnRowRejectsHeaderGarbage(t *testing.T) {
	colMap := fsutilCSVMap{usn: 4, timestamp: 5, reason: 6, fileName: 10}
	row := []string{"2", "0", "0x1", "0x2", "Reason", "Time stamp", "0x0", "Source info #", "0x0", "0x0", "0x00000000"}
	if ev := mapFsutilUsnRow(row, colMap); ev != nil {
		t.Fatalf("expected nil for header-like row, got %#v", ev)
	}
}

func TestUsnEventsLookInvalid(t *testing.T) {
	bad := []map[string]any{{"fileName": "0x00000000", "usn": "File create"}}
	if !usnEventsLookInvalid(bad) {
		t.Fatal("expected invalid")
	}
	good := []map[string]any{{"fileName": "hosts", "usn": "0x0000000016e93870"}}
	if usnEventsLookInvalid(good) {
		t.Fatal("expected valid")
	}
}
