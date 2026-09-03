//go:build windows

package collectors

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"

	"github.com/quarantine-lab/quarantine/internal/agent/types"
)

// SaveRegistryHives dumps live hives with `reg save` for offline indexing on the host.
// Avoids multi-GB snapshot disk flatten for Compare.
func SaveRegistryHives(snapshotName, payloadUser string) (*types.HiveDump, error) {
	safe := sanitizeSnap(snapshotName)
	outDir := filepath.Join(`C:\Users\Public\Quarantine\hives`, safe)
	_ = os.RemoveAll(outDir)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}

	dump := &types.HiveDump{GuestDir: outDir}
	specs := []struct {
		key    string
		file   string
		prefix string
	}{
		{`HKLM\SOFTWARE`, "SOFTWARE", `HKLM:\SOFTWARE`},
		{`HKLM\SYSTEM`, "SYSTEM", `HKLM:\SYSTEM`},
		{`HKU\.DEFAULT`, "DEFAULT", `HKU:\.DEFAULT`},
		{`HKLM\SAM`, "SAM", `HKLM:\SAM`},
		{`HKLM\SECURITY`, "SECURITY", `HKLM:\SECURITY`},
	}
	for _, s := range specs {
		dest := filepath.Join(outDir, s.file)
		if err := regSave(s.key, dest); err != nil {
			dump.Warnings = append(dump.Warnings, fmt.Sprintf("%s: %v", s.key, err))
			continue
		}
		dump.Files = append(dump.Files, types.HiveFile{
			Name:      s.file,
			GuestPath: dest,
			Prefix:    s.prefix,
		})
	}

	if sid, err := resolvePayloadSID(payloadUser); err == nil && sid != "" {
		dest := filepath.Join(outDir, "NTUSER_"+sanitizeSnap(sid))
		key := `HKU\` + sid
		if err := regSave(key, dest); err != nil {
			dump.Warnings = append(dump.Warnings, fmt.Sprintf("%s: %v", key, err))
		} else {
			dump.Files = append(dump.Files, types.HiveFile{
				Name:      filepath.Base(dest),
				GuestPath: dest,
				Prefix:    `HKU:\` + sid,
			})
		}
	} else if err != nil {
		dump.Warnings = append(dump.Warnings, "payload hive: "+err.Error())
	}

	if len(dump.Files) == 0 {
		return dump, fmt.Errorf("no hives saved")
	}
	return dump, nil
}

func regSave(key, dest string) error {
	cmd := exec.Command("reg", "save", key, dest, "/y")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	st, err := os.Stat(dest)
	if err != nil {
		return err
	}
	if st.Size() < 16 {
		return fmt.Errorf("empty hive file")
	}
	return nil
}

func resolvePayloadSID(payloadUser string) (string, error) {
	payloadUser = strings.TrimSpace(payloadUser)
	if payloadUser == "" {
		return "", fmt.Errorf("no payload user")
	}
	if token, sid, _, err := userSessionToken(payloadUser); err == nil {
		token.Close()
		if sid != "" {
			return sid, nil
		}
	}
	k, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return "", err
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return "", err
	}
	var candidates []string
	for _, n := range names {
		if strings.HasPrefix(n, "S-1-5-21-") && !strings.Contains(n, "_Classes") {
			candidates = append(candidates, n)
		}
	}
	for _, sid := range candidates {
		if matchProfileUser(sid, payloadUser) {
			return sid, nil
		}
	}
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	return "", fmt.Errorf("no interactive HKU hive loaded for %s", payloadUser)
}

func matchProfileUser(sid, wantUser string) bool {
	path := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\` + sid
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	img, _, err := k.GetStringValue("ProfileImagePath")
	if err != nil {
		return false
	}
	return strings.EqualFold(filepath.Base(img), wantUser)
}

func sanitizeSnap(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "snap"
	}
	return strings.Map(func(r rune) rune {
		switch r {
		case ':', '/', '\\', '*', '?', '"', '<', '>', '|', ' ':
			return '_'
		default:
			return r
		}
	}, s)
}
