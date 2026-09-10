package collectors

import "testing"

func TestSysmonFileChangeKind(t *testing.T) {
	cases := []struct {
		eid  int
		typ  string
		want string
		ok   bool
	}{
		{11, "FileCreate", "added", true},
		{15, "FileCreateStreamHash", "added", true},
		{12, "RegistryEvent", "", false},
		{23, "FileDelete", "removed", true},
		{26, "FileDeleteDetected", "removed", true},
		{2, "FileCreateTime", "modified", true},
		{1, "ProcessCreate", "", false},
	}
	for _, tc := range cases {
		got, ok := SysmonFileChangeKind(tc.eid, tc.typ)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("SysmonFileChangeKind(%d, %q) = (%q, %v), want (%q, %v)", tc.eid, tc.typ, got, ok, tc.want, tc.ok)
		}
	}
}

func TestMergeFileChangeKind(t *testing.T) {
	m := map[string]string{}
	mergeFileChangeKind(m, `C:\Windows\System32\drivers\etc\hosts`, "added")
	mergeFileChangeKind(m, `C:\Windows\System32\drivers\etc\hosts`, "modified")
	if m[`C:\Windows\System32\drivers\etc\hosts`] != "added" {
		t.Fatalf("create then write should stay added, got %q", m[`C:\Windows\System32\drivers\etc\hosts`])
	}
	n := map[string]string{}
	mergeFileChangeKind(n, `C:\Windows\System32\drivers\etc\hosts`, "modified")
	mergeFileChangeKind(n, `C:\Windows\System32\drivers\etc\hosts`, "added")
	if n[`C:\Windows\System32\drivers\etc\hosts`] != "modified" {
		t.Fatalf("USN modify then Sysmon FileCreate should stay modified, got %q", n[`C:\Windows\System32\drivers\etc\hosts`])
	}
	mergeFileChangeKind(m, `C:\temp\gone.txt`, "added")
	mergeFileChangeKind(m, `C:\temp\gone.txt`, "removed")
	if m[`C:\temp\gone.txt`] != "removed" {
		t.Fatalf("expected removed, got %q", m[`C:\temp\gone.txt`])
	}
	mergeFileChangeKind(m, `C:\Windows\System32\dodge.txt`, "removed")
	mergeFileChangeKind(m, `C:\Windows\System32\dodge.txt`, "added")
	if m[`C:\Windows\System32\dodge.txt`] != "added" {
		t.Fatalf("later create should win, got %q", m[`C:\Windows\System32\dodge.txt`])
	}
}
