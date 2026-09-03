//go:build windows

package privileges

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modAdvapi32                   = windows.NewLazySystemDLL("advapi32.dll")
	procImpersonateLoggedOnUser   = modAdvapi32.NewProc("ImpersonateLoggedOnUser")
	procRevertToSelf              = modAdvapi32.NewProc("RevertToSelf")
)

var backupPrivs = []string{
	"SeBackupPrivilege",
	"SeRestorePrivilege",
	"SeSecurityPrivilege",
	"SeManageVolumePrivilege",
	"SeTcbPrivilege",
	"SeImpersonatePrivilege",
	"SeAssignPrimaryTokenPrivilege",
}

// EnableManifestRead enables privileges needed for USN journal and event log reads.
func EnableManifestRead() error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()

	for _, name := range backupPrivs {
		var luid windows.LUID
		if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid); err != nil {
			continue
		}
		tp := windows.Tokenprivileges{
			PrivilegeCount: 1,
			Privileges: [1]windows.LUIDAndAttributes{
				{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
			},
		}
		_ = windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
	}
	return nil
}

// ImpersonateUser runs fn as the given user token.
func ImpersonateUser(token windows.Token, fn func() error) error {
	r0, _, e1 := procImpersonateLoggedOnUser.Call(uintptr(token))
	if r0 == 0 {
		return fmt.Errorf("ImpersonateLoggedOnUser: %w", e1)
	}
	defer procRevertToSelf.Call()
	return fn()
}

// DuplicateImpersonationToken returns a primary token suitable for impersonation.
func DuplicateImpersonationToken(token windows.Token) (windows.Token, error) {
	var dup windows.Token
	err := windows.DuplicateTokenEx(
		token,
		windows.MAXIMUM_ALLOWED,
		nil,
		windows.SecurityImpersonation,
		windows.TokenImpersonation,
		&dup,
	)
	if err != nil {
		return 0, err
	}
	return dup, nil
}

var _ = unsafe.Pointer(nil)
