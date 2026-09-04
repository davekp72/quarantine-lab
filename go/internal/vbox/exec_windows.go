//go:build windows

package vbox

import (
	"os/exec"
	"syscall"
)

// prepareCmd configures VBoxManage so it does not flash a console and can load
// VirtualBox DLLs reliably when spawned from the Wails UI.
func prepareCmd(cmd *exec.Cmd, vboxDir string) {
	cmd.Dir = vboxDir
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
}
