//go:build !windows

package pcapinspect

import "os/exec"

func hideConsole(cmd *exec.Cmd) {}
