package applog

import "testing"

func TestNormalizeAndRank(t *testing.T) {
	if NormalizeLevel("cmd") != LevelDebug {
		t.Fatal("cmd should be debug")
	}
	if NormalizeLevel("WARNING") != LevelWarn {
		t.Fatal("WARNING should be warn")
	}
	if Rank(LevelDebug) >= Rank(LevelInfo) {
		t.Fatal("debug < info")
	}
	if Rank(LevelInfo) >= Rank(LevelWarn) {
		t.Fatal("info < warn")
	}
	if Rank(LevelWarn) >= Rank(LevelError) {
		t.Fatal("warn < error")
	}
}

func TestLinesAtLeast(t *testing.T) {
	b := New(100)
	b.Add("cmd", "VBoxManage showvminfo")
	b.Add("info", "Snapshot saved")
	b.Add("error", "boom")
	got := b.LinesAtLeast(LevelInfo)
	if len(got) != 2 {
		t.Fatalf("want 2, got %d %#v", len(got), got)
	}
	if got[0].Level != LevelInfo || got[1].Level != LevelError {
		t.Fatalf("%#v", got)
	}
}
