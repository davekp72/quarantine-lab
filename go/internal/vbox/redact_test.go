package vbox

import (
	"strings"
	"testing"
)

func TestRedactSecretsPasswordArgs(t *testing.T) {
	secret := "SuperSecret-Passw0rd!"
	in := `VBoxManage guestcontrol Lab run --username=quarantine --password=` + secret + ` --exe C:\Windows\System32\cmd.exe`
	out := RedactSecrets(in)
	if strings.Contains(out, secret) {
		t.Fatalf("secret still present: %s", out)
	}
	if !strings.Contains(out, "--password=***") {
		t.Fatalf("expected placeholder: %s", out)
	}
}

func TestRedactSecretsPrintfSudo(t *testing.T) {
	secret := "gw-root-s3cret"
	in := `printf '%s\n' '` + secret + `' | sudo -S -p '' bash -c 'id'`
	out := RedactSecrets(in)
	if strings.Contains(out, secret) {
		t.Fatalf("secret still present: %s", out)
	}
}

func TestRedactSecretsPasswordFile(t *testing.T) {
	in := `guestcontrol X copyto --passwordfile=C:\Temp\qlab-vbox-pw-123.tmp --username=u`
	out := RedactSecrets(in)
	if strings.Contains(out, `qlab-vbox-pw-123.tmp`) {
		t.Fatalf("password file path should be redacted: %s", out)
	}
}

func TestFormatArgsNeverLeaksMarker(t *testing.T) {
	const marker = "MARK-SECRET-XYZ-NEVER-LOG"
	got := FormatArgs([]string{
		"guestcontrol", "VM", "run",
		"--password=" + marker,
		"--exe", "/bin/bash",
		"-lc", "printf '%s\\n' '" + marker + "' | sudo -S -p '' id",
	})
	if strings.Contains(got, marker) {
		t.Fatalf("leaked marker in: %s", got)
	}
}

func TestAuthFlagsUsesPasswordFile(t *testing.T) {
	args, cleanup, err := AuthFlags("user", "MARK-SECRET-XYZ-NEVER-LOG")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "MARK-SECRET-XYZ-NEVER-LOG") {
		t.Fatalf("password in auth args: %s", joined)
	}
	if !strings.Contains(joined, "--passwordfile=") {
		t.Fatalf("expected passwordfile: %s", joined)
	}
	if strings.Contains(joined, "--password=") {
		t.Fatalf("must not use --password=: %s", joined)
	}
}
