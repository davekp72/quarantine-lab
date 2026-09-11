package collectors

import (
	"testing"
	"time"
)

func TestClassifyFileNoise(t *testing.T) {
	cases := []struct {
		path, name, class string
	}{
		{`C:\Windows\System32\dodge.txt`, "dodge.txt", ""},
		{`C:\Windows\System32\drivers\etc\hosts`, "hosts", ""},
		{`C:\Windows\System32\evil.dll`, "evil.dll", ""},
		{`C:\Windows\SystemTemp\drop.exe`, "drop.exe", ""},
		{`C:\Windows\SystemTemp\abcdefg.dll`, "abcdefg.dll", ""},
		{`C:\Users\jkcooper\AppData\Local\Temp\drop.exe`, "drop.exe", ""},
		{`C:\Users\jkcooper\AppData\Local\Temp\foo.txt`, "foo.txt", "temp"},
		{`C:\Windows\Prefetch\NOTEPAD.EXE-123.pf`, "NOTEPAD.EXE-123.pf", "os_telemetry"},
		{`C:\Users\Public\Quarantine\hives\SOFTWARE`, "SOFTWARE", "capture"},
		{`C:\ProgramData\QuarantineLab\hives\SOFTWARE`, "SOFTWARE", "capture"},
		{`C:\Program Files\QuarantineLab\quarantine-agent.exe`, "quarantine-agent.exe", "capture"},
		{`C:\Users\Public\Quarantine\hklm-registry-cli\hklm-HKLM_Software.reg`, "hklm-HKLM_Software.reg", "capture"},
		{`C:\Windows\System32\config\systemprofile\AppData\Local\x.dat`, "x.dat", "os_telemetry"},
		{`C:\Users\jkcooper\AppData\Local\Microsoft\Windows\INetCache\foo`, "foo", "os_telemetry"},
		{`C:\Users\jkcooper\AppData\Roaming\Microsoft\Windows\Recent\System32.lnk`, "System32.lnk", "os_telemetry"},
		{`C:\$Extend\$Deleted\00020000000408F673F5ACE4`, "00020000000408F673F5ACE4", "ntfs"},
		{`C:\Windows\ServiceState\WinHttpAutoProxySvc\Data\1616699711.cache`, "1616699711.cache", "os_telemetry"},
		{`C:\Windows\SystemTemp\__PSScriptPolicyTest_t2xeymyi.jvb.ps1`, "__PSScriptPolicyTest_t2xeymyi.jvb.ps1", "temp"},
		{`C:\Windows\SystemTemp\50ylbunx\50ylbunx.dll`, "50ylbunx.dll", "temp"},
		{`C:\Windows\SystemTemp\50ylbunx`, "50ylbunx", "temp"},
		{"dvhh5xui.0.cs", "dvhh5xui.0.cs", "temp"},
		{`C:\Users\jkcooper\AppData\Local\Microsoft\OneDrive\26.153.0809.0004\FileSync.dll`, "FileSync.dll", "onedrive_client"},
		{`C:\Users\jkcooper\OneDrive\Documents\notes.txt`, "notes.txt", ""},
		{"", "NTUSER.DAT", "os_telemetry"},
		{"", "hosts", ""},
		{"", "Report.wer.tmp", "os_telemetry"},
	}
	for _, tc := range cases {
		got := ClassifyFileNoise(tc.path, tc.name)
		if got != tc.class {
			t.Fatalf("ClassifyFileNoise(%q, %q)=%q want %q", tc.path, tc.name, got, tc.class)
		}
	}
}

func TestFilePrioritySystem32First(t *testing.T) {
	if FilePriority(`C:\Windows\System32\dodge.txt`) >= FilePriority(`C:\Users\jkcooper\Downloads\a.txt`) {
		t.Fatal("System32 should outrank user downloads")
	}
}

func TestParseUsnValueHex(t *testing.T) {
	n, err := parseUsnValue("0x0000000018c78b00")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0x18c78b00 {
		t.Fatalf("got 0x%x", n)
	}
	if _, err := parseUsnValue(""); err == nil {
		t.Fatal("expected error")
	}
}

func TestFinalizeUSNEventsDropsOldAndNoise(t *testing.T) {
	events := []map[string]any{
		{"usn": "0x0000000016800000", "fileName": "old.txt", "reason": []string{"file_create"}, "path": `C:\Windows\System32\old.txt`},
		{"usn": "0x0000000018c78b10", "fileName": "NTUSER.DAT", "reason": []string{"data_overwrite"}, "path": `C:\Users\jkcooper\NTUSER.DAT`},
		{"usn": "0x0000000018c78b20", "fileName": "dodge.txt", "reason": []string{"file_create"}, "path": `C:\Windows\System32\dodge.txt`},
		{"usn": "0x0000000018c78b30", "fileName": "cache", "reason": []string{"close"}, "reasonCode": "0x80000000", "path": `C:\tmp\cache`},
		{"usn": "0x0000000018c78b40", "fileName": "hosts", "reason": []string{"data_overwrite"}, "path": `C:\Windows\System32\drivers\etc\hosts`},
	}
	kept, noise, skipped := FinalizeUSNEvents("C:", events, 0x18c78b00, timeZero())
	if skipped != 1 {
		t.Fatalf("skipped=%d", skipped)
	}
	if noise["os_telemetry"] < 1 {
		t.Fatalf("noise=%v", noise)
	}
	if noise["close_only"] < 1 {
		t.Fatalf("close not counted: %v", noise)
	}
	got := map[string]string{}
	for _, ev := range kept {
		p, _ := ev["path"].(string)
		got[p] = ev["change"].(string)
	}
	if got[`C:\Windows\System32\dodge.txt`] != "added" {
		t.Fatalf("missing dodge.txt: %+v", got)
	}
	if got[`C:\Windows\System32\drivers\etc\hosts`] != "modified" {
		t.Fatalf("missing hosts: %+v", got)
	}
	if _, ok := got[`C:\Windows\System32\old.txt`]; ok {
		t.Fatal("pre-baseline event should be dropped")
	}
}

func TestFinalizeUSNRecreateIsAdded(t *testing.T) {
	events := []map[string]any{
		{"usn": "0x10", "fileName": "dodge.txt", "reason": []string{"file_create"}, "path": `C:\Windows\System32\dodge.txt`},
		{"usn": "0x11", "fileName": "dodge.txt", "reason": []string{"file_delete"}, "path": `C:\Windows\System32\dodge.txt`},
		{"usn": "0x12", "fileName": "dodge.txt", "reason": []string{"file_create", "data_truncation"}, "path": `C:\Windows\System32\dodge.txt`},
	}
	kept, _, _ := FinalizeUSNEvents("C:", events, 0, timeZero())
	if len(kept) != 1 {
		t.Fatalf("kept=%d %+v", len(kept), kept)
	}
	if kept[0]["change"] != "added" {
		t.Fatalf("recreate should be added, got %v", kept[0]["change"])
	}
}

func timeZero() time.Time { return time.Time{} }
