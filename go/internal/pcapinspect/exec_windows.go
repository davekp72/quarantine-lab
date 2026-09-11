//go:build windows

package pcapinspect

import (
	"os/exec"
	"syscall"
)

// hideConsole prevents tshark from flashing a console window when spawned from the UI.
func hideConsole(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
}
