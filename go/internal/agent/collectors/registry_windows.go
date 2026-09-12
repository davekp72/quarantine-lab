//go:build windows

package collectors

import (
	"fmt"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"github.com/quarantine-lab/quarantine/internal/agent/privileges"
	"github.com/quarantine-lab/quarantine/internal/agent/types"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	modWtsapi32                     = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSEnumerateSessions        = modWtsapi32.NewProc("WTSEnumerateSessionsW")
	procWTSQuerySessionInformationW = modWtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory               = modWtsapi32.NewProc("WTSFreeMemory")
	procWTSQueryUserToken           = modWtsapi32.NewProc("WTSQueryUserToken")
)

const (
	wtsCurrentServerHandle = 0
	wtsUserName            = 5
)

type wtsSessionInfo struct {
	SessionID      uint32
	WinStationName *uint16
	State          uint32
}

var hklmRoots = []struct {
	path   string
	prefix string
}{
	{`Software\QuarantineLab`, `HKLM:\Software\QuarantineLab`},
	{`Software\Microsoft\Windows\CurrentVersion`, `HKLM:\Software\Microsoft\Windows\CurrentVersion`},
	{`Software\Microsoft\Windows\CurrentVersion\Run`, `HKLM:\Software\Microsoft\Windows\CurrentVersion\Run`},
	{`Software\Microsoft\Windows\CurrentVersion\RunOnce`, `HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce`},
	{`Software\WOW6432Node\Microsoft\Windows\CurrentVersion`, `HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion`},
	{`Software\Microsoft\Windows NT\CurrentVersion`, `HKLM:\Software\Microsoft\Windows NT\CurrentVersion`},
	{`SYSTEM\CurrentControlSet\Services`, `HKLM:\SYSTEM\CurrentControlSet\Services`},
	{`SYSTEM\CurrentControlSet\Control\Session Manager`, `HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager`},
	{`Software\Oracle\VirtualBox Guest Additions`, `HKLM:\Software\Oracle\VirtualBox Guest Additions`},
}

var hkcuRoots = []struct {
	path   string
	prefix string
}{
	{`Software`, `HKCU:\Software`},
	{`Environment`, `HKCU:\Environment`},
	{`Volatile Environment`, `HKCU:\Volatile Environment`},
	{`Console`, `HKCU:\Console`},
	{`Software\Microsoft\Windows\CurrentVersion\Run`, `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`},
	{`Software\Microsoft\Windows\CurrentVersion\RunOnce`, `HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce`},
}

// Shared HKU hives (not the interactive payload user) that malware/lab edits often target.
var hkuSharedRoots = []struct {
	path   string
	prefix string
}{
	{`.DEFAULT\Software`, `HKU:\.DEFAULT\Software`},
	{`.DEFAULT\System`, `HKU:\.DEFAULT\System`},
	{`.DEFAULT\Environment`, `HKU:\.DEFAULT\Environment`},
	{`S-1-5-18\Software`, `HKU:\S-1-5-18\Software`},
	{`S-1-5-18\System`, `HKU:\S-1-5-18\System`},
	{`S-1-5-19\Software`, `HKU:\S-1-5-19\Software`},
	{`S-1-5-20\Software`, `HKU:\S-1-5-20\Software`},
}

// ExportHKLM walks predefined HKLM keys.
func ExportHKLM() ([]types.RegistryEntry, error) {
	var entries []types.RegistryEntry
	for _, root := range hklmRoots {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, root.path, registry.READ|registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		walkKey(k, root.prefix, &entries, 20000)
		k.Close()
	}
	return entries, nil
}

// ExportHKUShared walks .DEFAULT and well-known system user hives under HKEY_USERS.
func ExportHKUShared() ([]types.RegistryEntry, error) {
	var entries []types.RegistryEntry
	for _, root := range hkuSharedRoots {
		k, err := registry.OpenKey(registry.USERS, root.path, registry.READ|registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		walkKey(k, root.prefix, &entries, 10000)
		k.Close()
	}
	return entries, nil
}

// PayloadIdentity resolves the payload user's SID without walking HKCU.
func PayloadIdentity(payloadUser string) (sid, user string, err error) {
	token, sid, user, err := userSessionToken(payloadUser)
	if err != nil {
		return "", "", err
	}
	token.Close()
	return sid, user, nil
}

// ExportHKCU exports payload user registry via impersonation.
func ExportHKCU(payloadUser string) ([]types.RegistryEntry, string, string, error) {
	if strings.TrimSpace(payloadUser) == "" {
		return nil, "", "", fmt.Errorf("payload user not configured")
	}
	token, sid, user, err := userSessionToken(payloadUser)
	if err != nil {
		return nil, "", "", err
	}
	defer token.Close()

	var entries []types.RegistryEntry
	err = privileges.ImpersonateUser(token, func() error {
		for _, root := range hkcuRoots {
			k, err := registry.OpenKey(registry.CURRENT_USER, root.path, registry.READ|registry.ENUMERATE_SUB_KEYS)
			if err != nil {
				continue
			}
			mappedPrefix := strings.Replace(root.prefix, `HKCU:`, `HKU:\`+sid, 1)
			walkKey(k, mappedPrefix, &entries, 20000)
			k.Close()
		}
		return nil
	})
	return entries, sid, user, err
}

// PayloadSessionActive reports whether payload user has an interactive session.
func PayloadSessionActive(payloadUser string) (bool, string) {
	_, _, user, err := userSessionToken(payloadUser)
	if err != nil {
		return false, ""
	}
	return true, user
}

// InteractiveUserToken returns a duplicated impersonation token for a logged-on user.
func InteractiveUserToken(username string) (windows.Token, string, string, error) {
	return userSessionToken(username)
}

func userSessionToken(username string) (windows.Token, string, string, error) {
	sessions, err := enumerateSessions()
	if err != nil {
		return 0, "", "", err
	}

	target := strings.ToLower(username)
	var candidates []wtsSessionInfo
	for _, s := range sessions {
		switch s.State {
		case windows.WTSActive, windows.WTSConnected, windows.WTSDisconnected:
			candidates = append(candidates, s)
		}
	}
	// Prefer active/connected sessions, then disconnected (locked desktop).
	sort.SliceStable(candidates, func(i, j int) bool {
		rank := func(st uint32) int {
			switch st {
			case windows.WTSActive:
				return 0
			case windows.WTSConnected:
				return 1
			default:
				return 2
			}
		}
		return rank(candidates[i].State) < rank(candidates[j].State)
	})

	var lastErr error
	for _, s := range candidates {
		user, err := querySessionUserName(s.SessionID)
		if err != nil {
			continue
		}
		if strings.ToLower(user) != target {
			continue
		}
		_ = privileges.EnableManifestRead()
		var token windows.Token
		r0, _, e1 := procWTSQueryUserToken.Call(uintptr(s.SessionID), uintptr(unsafe.Pointer(&token)))
		if r0 == 0 {
			lastErr = fmt.Errorf("WTSQueryUserToken: %v", e1)
			continue
		}
		sid, err := tokenUserSID(token)
		if err != nil {
			token.Close()
			lastErr = err
			continue
		}
		dup, err := privileges.DuplicateImpersonationToken(token)
		token.Close()
		if err != nil {
			lastErr = err
			continue
		}
		return dup, sid, user, nil
	}
	if lastErr != nil {
		return 0, "", "", lastErr
	}
	return 0, "", "", fmt.Errorf("no active session for payload user %q (log in inside the VM)", username)
}

func enumerateSessions() ([]wtsSessionInfo, error) {
	var infoPtr *wtsSessionInfo
	var count uint32
	r0, _, e1 := procWTSEnumerateSessions.Call(
		wtsCurrentServerHandle, 0, 1,
		uintptr(unsafe.Pointer(&infoPtr)), uintptr(unsafe.Pointer(&count)),
	)
	if r0 == 0 {
		return nil, fmt.Errorf("WTSEnumerateSessions: %v", e1)
	}
	defer procWTSFreeMemory.Call(uintptr(unsafe.Pointer(infoPtr)))

	if count == 0 {
		return nil, nil
	}
	// Copy session slice from C memory
	header := unsafe.Slice(infoPtr, count)
	out := make([]wtsSessionInfo, count)
	copy(out, header)
	return out, nil
}

func querySessionUserName(sessionID uint32) (string, error) {
	var buf *uint16
	var bytes uint32
	r0, _, e1 := procWTSQuerySessionInformationW.Call(
		wtsCurrentServerHandle, uintptr(sessionID), wtsUserName,
		uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&bytes)),
	)
	if r0 == 0 {
		return "", e1
	}
	defer procWTSFreeMemory.Call(uintptr(unsafe.Pointer(buf)))
	return windows.UTF16PtrToString(buf), nil
}

func tokenUserSID(token windows.Token) (string, error) {
	var size uint32
	_ = windows.GetTokenInformation(token, windows.TokenUser, nil, 0, &size)
	buf := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenUser, &buf[0], size, &size); err != nil {
		return "", err
	}
	user := (*windows.Tokenuser)(unsafe.Pointer(&buf[0]))
	return user.User.Sid.String(), nil
}

func walkKey(k registry.Key, prefix string, entries *[]types.RegistryEntry, max int) {
	if len(*entries) >= max {
		return
	}
	names, err := k.ReadValueNames(-1)
	if err == nil {
		for _, name := range names {
			if len(*entries) >= max {
				return
			}
			val, valType, err := k.GetStringValue(name)
			if err == nil {
				*entries = append(*entries, types.RegistryEntry{
					K: prefix, N: name, T: regTypeName(valType), V: val,
				})
				continue
			}
			b, valType, err := k.GetBinaryValue(name)
			if err == nil {
				*entries = append(*entries, types.RegistryEntry{
					K: prefix, N: name, T: regTypeName(valType), V: fmt.Sprintf("%x", b),
				})
				continue
			}
			i, valType, err := k.GetIntegerValue(name)
			if err == nil {
				*entries = append(*entries, types.RegistryEntry{
					K: prefix, N: name, T: regTypeName(valType), V: fmt.Sprintf("0x%08x", i),
				})
			}
		}
	}
	subkeys, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return
	}
	for _, sub := range subkeys {
		if len(*entries) >= max {
			return
		}
		sk, err := registry.OpenKey(k, sub, registry.READ|registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		walkKey(sk, prefix+`\`+sub, entries, max)
		sk.Close()
	}
}

func regTypeName(t uint32) string {
	switch t {
	case registry.SZ:
		return "REG_SZ"
	case registry.EXPAND_SZ:
		return "REG_EXPAND_SZ"
	case registry.DWORD:
		return "REG_DWORD"
	case registry.QWORD:
		return "REG_QWORD"
	case registry.BINARY:
		return "REG_BINARY"
	case registry.MULTI_SZ:
		return "REG_MULTI_SZ"
	default:
		return fmt.Sprintf("REG_%d", t)
	}
}

var _ = syscall.Errno(0)
