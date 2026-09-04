//go:build !windows

package vbox

import "os/exec"

func prepareCmd(cmd *exec.Cmd, vboxDir string) {
	if vboxDir != "" {
		cmd.Dir = vboxDir
	}
}
