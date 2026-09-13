//go:build windows

package winacl

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestProtectRemovesUsersACE(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "qlab-acl")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckProtected(dir); err == nil {
		// Some runners already omit Users/Everyone from %TEMP%. Add a
		// well-known extra ACE so CheckProtected still has something to reject.
		if out, grantErr := exec.Command("icacls", dir, "/grant", "Users:(OI)(CI)(RX)").CombinedOutput(); grantErr != nil {
			t.Fatalf("grant Users for test setup: %v (%s)", grantErr, strings.TrimSpace(string(out)))
		}
		if err := CheckProtected(dir); err == nil {
			t.Fatal("Users ACE should fail CheckProtected")
		}
	}
	if err := Protect(dir); err != nil {
		t.Skip("Protect requires Administrators: " + err.Error())
	}
	t.Cleanup(func() {
		user := os.Getenv("USERNAME")
		if user != "" {
			_ = exec.Command("icacls", dir, "/grant", user+":(OI)(CI)F").Run()
		}
	})
	if err := CheckProtected(dir); err != nil {
		t.Fatal(err)
	}
}
