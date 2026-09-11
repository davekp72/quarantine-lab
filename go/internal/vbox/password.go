package vbox

import (
	"fmt"
	"os"
)

// AuthFlags builds guestcontrol auth args using a temporary password file
// so the password never appears on the VBoxManage command line.
// Caller must invoke cleanup (usually via defer) after Run returns.
func AuthFlags(username, password string) (args []string, cleanup func(), err error) {
	f, err := os.CreateTemp("", "qlab-vbox-pw-*.tmp")
	if err != nil {
		return nil, func() {}, err
	}
	path := f.Name()
	cleanup = func() { _ = os.Remove(path) }

	if _, err := f.WriteString(password); err != nil {
		_ = f.Close()
		cleanup()
		return nil, func() {}, fmt.Errorf("write password file: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return nil, func() {}, err
	}
	// Best-effort: restrict to current user on platforms that honor chmod.
	_ = os.Chmod(path, 0o600)

	return []string{
		"--username=" + username,
		"--passwordfile=" + path,
	}, cleanup, nil
}
