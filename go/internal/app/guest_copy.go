package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/quarantine-lab/quarantine/internal/agent/guestpaths"
)

// CopyHostFileToGuest copies one host file into the guest and returns the guest path.
// The VM must already be running; this does not start it or change NAT/port-forwards.
func (a *App) CopyHostFileToGuest(hostPath, guestDir string) (string, error) {
	if a == nil || a.Cfg == nil || a.Evidence == nil || a.Evidence.Guest == nil {
		return "", fmt.Errorf("app not initialized")
	}
	abs, dest, dir, err := guestCopyDest(hostPath, guestDir, a.Cfg.Guest.CopyTargetDir)
	if err != nil {
		return "", err
	}
	if err := a.Evidence.Guest.CopyTo(abs, dir, a.Evidence.Guest.GuestCreds()); err != nil {
		return "", err
	}
	return dest, nil
}

func guestCopyDest(hostPath, guestDir, defaultDir string) (absHost, dest, dir string, err error) {
	absHost, err = filepath.Abs(hostPath)
	if err != nil {
		return "", "", "", err
	}
	st, err := os.Stat(absHost)
	if err != nil {
		return "", "", "", err
	}
	if st.IsDir() {
		return "", "", "", fmt.Errorf("%s is a directory", absHost)
	}
	dir = strings.TrimSpace(guestDir)
	if dir == "" {
		dir = strings.TrimSpace(defaultDir)
	}
	if dir == "" {
		dir = guestpaths.PublicDir
	}
	return absHost, guestpaths.GuestJoin(dir, filepath.Base(absHost)), dir, nil
}
