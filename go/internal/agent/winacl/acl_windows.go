//go:build windows

package winacl

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/quarantine-lab/quarantine/internal/agent/guestpaths"
	"golang.org/x/sys/windows"
)

const labUserAccess = windows.GENERIC_READ | windows.GENERIC_EXECUTE

// Protect sets a SYSTEM + Administrators DACL (no Users/Everyone), plus RX for
// the lab guestcontrol account so unelevated VBox copyfrom can read the token.
func Protect(path string) error {
	if st, err := os.Stat(path); err == nil {
		if st.IsDir() {
			if err := os.MkdirAll(path, 0o700); err != nil {
				return err
			}
		}
	} else if os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return err
		}
	}
	if err := protectAPI(path); err == nil {
		return nil
	}
	return protectIcacls(path)
}

func protectAPI(path string) error {
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	var inherit uint32
	if st, err := os.Stat(path); err == nil && st.IsDir() {
		inherit = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	}
	entries := []windows.EXPLICIT_ACCESS{
		explicitGrant(systemSID, inherit, windows.GENERIC_ALL, windows.TRUSTEE_IS_GROUP),
		explicitGrant(adminSID, inherit, windows.GENERIC_ALL, windows.TRUSTEE_IS_GROUP),
	}
	for _, sid := range extraUserSIDs() {
		entries = append(entries, explicitGrant(sid, inherit, labUserAccess, windows.TRUSTEE_IS_USER))
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	)
}

func explicitGrant(sid *windows.SID, inherit uint32, perm windows.ACCESS_MASK, trusteeType windows.TRUSTEE_TYPE) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: perm,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inherit,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  trusteeType,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func protectIcacls(path string) error {
	systemGrant := "*S-1-5-18:F"
	adminGrant := "*S-1-5-32-544:F"
	userGrant := "%s:(RX)"
	if st, err := os.Stat(path); err == nil && st.IsDir() {
		systemGrant = "*S-1-5-18:(OI)(CI)F"
		adminGrant = "*S-1-5-32-544:(OI)(CI)F"
		userGrant = "%s:(OI)(CI)RX"
	}
	args := []string{path, "/inheritance:r", "/grant:r", systemGrant, adminGrant}
	for _, acct := range allowedLabUsers() {
		args = append(args, fmt.Sprintf(userGrant, acct))
	}
	cmd := exec.Command("icacls", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls protect %s: %w (%s)", path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// CheckProtected fails if Users/Everyone (or other unexpected principals) are on the DACL.
func CheckProtected(path string) error {
	out, err := exec.Command("icacls", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls %s: %w (%s)", path, err, strings.TrimSpace(string(out)))
	}
	allowed := allowedIdentities()
	var extras []string
	hasSystem, hasAdmin := false, false
	pathLower := strings.ToLower(path)
	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(strings.ToLower(line), "successfully processed") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, pathLower) {
			line = strings.TrimSpace(line[len(path):])
			lower = strings.ToLower(line)
		}
		ident := aclIdentity(line)
		if ident == "" {
			continue
		}
		switch {
		case ident == `nt authority\system` || ident == `s-1-5-18` || strings.HasSuffix(ident, `\system`):
			hasSystem = true
		case ident == `builtin\administrators` || ident == `s-1-5-32-544` || strings.HasSuffix(ident, `\administrators`):
			hasAdmin = true
		case allowed[ident]:
			continue
		default:
			extras = append(extras, ident)
		}
	}
	if len(extras) > 0 {
		return fmt.Errorf("%s DACL allows extra principals %s\n%s", path, strings.Join(extras, ", "), strings.TrimSpace(string(out)))
	}
	if !hasSystem {
		return fmt.Errorf("%s DACL missing SYSTEM\n%s", path, strings.TrimSpace(string(out)))
	}
	if !hasAdmin {
		return fmt.Errorf("%s DACL missing Administrators\n%s", path, strings.TrimSpace(string(out)))
	}
	return nil
}

func aclIdentity(line string) string {
	line = strings.TrimSpace(line)
	idx := strings.Index(line, ":(")
	if idx < 0 {
		idx = strings.LastIndex(line, ":")
	}
	if idx <= 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(line[:idx]))
}

// RememberGuestControlUser records the unelevated lab account so later SYSTEM
// Protect() calls keep an RX ACE for VirtualBox guestcontrol copyfrom.
func RememberGuestControlUser() {
	sid := currentUserSID()
	if sid == nil {
		return
	}
	name, domain, _, err := sid.LookupAccount("")
	if err != nil || name == "" {
		return
	}
	acct := name
	if domain != "" {
		acct = domain + `\` + name
	}
	_ = os.MkdirAll(guestpaths.DataDir, 0o700)
	_ = os.WriteFile(guestpaths.GuestControlUserFile(), []byte(acct+"\n"), 0o600)
}

func currentUserSID() *windows.SID {
	tok, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil
	}
	defer tok.Close()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return nil
	}
	sid, err := tu.User.Sid.Copy()
	if err != nil {
		return nil
	}
	if sid.IsWellKnown(windows.WinLocalSystemSid) {
		return nil
	}
	return sid
}

func extraUserSIDs() []*windows.SID {
	var sids []*windows.SID
	seen := map[string]bool{}
	add := func(sid *windows.SID) {
		if sid == nil {
			return
		}
		key := sid.String()
		if seen[key] {
			return
		}
		seen[key] = true
		sids = append(sids, sid)
	}
	add(currentUserSID())
	for _, acct := range extraAccountNames() {
		sid, _, _, err := windows.LookupSID("", acct)
		if err == nil {
			add(sid)
		}
	}
	return sids
}

func extraAccountNames() []string {
	raw, err := os.ReadFile(guestpaths.GuestControlUserFile())
	if err != nil {
		return nil
	}
	acct := strings.TrimSpace(string(raw))
	if acct == "" {
		return nil
	}
	return []string{acct}
}

func allowedLabUsers() []string {
	seen := map[string]bool{}
	var out []string
	add := func(acct string) {
		acct = strings.TrimSpace(acct)
		if acct == "" {
			return
		}
		key := strings.ToLower(acct)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, acct)
	}
	for _, acct := range extraAccountNames() {
		add(acct)
	}
	if sid := currentUserSID(); sid != nil {
		name, domain, _, err := sid.LookupAccount("")
		if err == nil && name != "" {
			if domain != "" {
				add(domain + `\` + name)
			} else {
				add(name)
			}
		}
	}
	return out
}

func allowedIdentities() map[string]bool {
	out := map[string]bool{}
	for _, acct := range allowedLabUsers() {
		lower := strings.ToLower(acct)
		out[lower] = true
		if i := strings.LastIndex(lower, `\`); i >= 0 {
			out[lower[i+1:]] = true
		}
	}
	return out
}
