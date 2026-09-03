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
		{12, "FileCreateStream", "added", true},
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
	if m[`C:\Windows\System32\drivers\etc\hosts`] != "modified" {
		t.Fatalf("expected modified, got %q", m[`C:\Windows\System32\drivers\etc\hosts`])
	}
	mergeFileChangeKind(m, `C:\temp\gone.txt`, "added")
	mergeFileChangeKind(m, `C:\temp\gone.txt`, "removed")
	if m[`C:\temp\gone.txt`] != "removed" {
		t.Fatalf("expected removed, got %q", m[`C:\temp\gone.txt`])
	}
}
