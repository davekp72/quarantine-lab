//go:build !windows

package cmdexec

import (
	"fmt"

	"github.com/quarantine-lab/quarantine/internal/agent/types"
)

// Run executes a command in the guest. Non-Windows builds are host-only.
func Run(req types.ExecRequest, cfg types.AgentConfig) types.ExecResponse {
	return types.ExecResponse{ExitCode: -1, Error: fmt.Sprintf("exec requires windows (user=%s exe=%s)", req.User, req.Exe)}
}
