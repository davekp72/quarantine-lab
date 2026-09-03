package diff

import "testing"

func TestIsEphemeralTempPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{`C:\Windows\SystemTemp\__PSScriptPolicyTest_ugmeaer1.thp.ps1`, true},
		{`C:\Users\Public\Quarantine\Install-QuarantineAgent.ps1`, false},
		{`C:\Windows\Temp\foo.ps1`, false},
	}
	for _, tc := range cases {
		if got := IsEphemeralTempPath(tc.path); got != tc.want {
			t.Fatalf("IsEphemeralTempPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
