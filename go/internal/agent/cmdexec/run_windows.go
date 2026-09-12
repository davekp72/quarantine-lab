//go:build windows

package cmdexec

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"github.com/quarantine-lab/quarantine/internal/agent/collectors"
	"github.com/quarantine-lab/quarantine/internal/agent/guestpaths"
	"github.com/quarantine-lab/quarantine/internal/agent/privileges"
	"github.com/quarantine-lab/quarantine/internal/agent/types"
	"golang.org/x/sys/windows"
)

// Run starts exe as SYSTEM or in a logged-on user's WTS session.
func Run(req types.ExecRequest, cfg types.AgentConfig) types.ExecResponse {
	pol := policy(cfg)
	if err := pol.AllowedExec(req.Exe); err != nil {
		return types.ExecResponse{ExitCode: -1, Error: err.Error()}
	}
	role, username := resolveUser(req, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), timeoutOf(req))
	defer cancel()

	cmd := exec.CommandContext(ctx, req.Exe, req.Args...)
	cmd.Dir = guestpaths.PublicDir
	if role != "system" {
		if username == "" {
			return types.ExecResponse{ExitCode: -1, Error: fmt.Sprintf("no username configured for exec user %q", role)}
		}
		tok, _, _, err := collectors.InteractiveUserToken(username)
		if err != nil {
			return types.ExecResponse{ExitCode: -1, Error: err.Error() + " (log the user into the VM desktop, or pass --guest-additions)"}
		}
		defer tok.Close()
		primary, err := privileges.DuplicatePrimaryToken(tok)
		if err != nil {
			return types.ExecResponse{ExitCode: -1, Error: "duplicate primary token: " + err.Error()}
		}
		defer primary.Close()
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Token:         syscall.Token(primary),
			CreationFlags: windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_NEW_CONSOLE,
		}
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	resp := types.ExecResponse{
		Stdout: strings.TrimRight(stdout.String(), "\r\n"),
		Stderr: strings.TrimRight(stderr.String(), "\r\n"),
	}
	if cmd.ProcessState != nil {
		resp.ExitCode = cmd.ProcessState.ExitCode()
	} else if err != nil {
		resp.ExitCode = -1
	}
	if err != nil && resp.ExitCode == 0 {
		resp.Error = err.Error()
		resp.ExitCode = -1
	} else if err != nil && ctx.Err() != nil {
		resp.Error = "exec timed out"
	}
	return resp
}
