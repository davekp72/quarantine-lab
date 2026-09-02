//go:build !windows

package capture

import (
	"fmt"

	"github.com/quarantine-lab/quarantine/internal/agent/types"
)

func Run(req types.CaptureRequest, cfg types.AgentConfig) (*types.CaptureResponse, error) {
	return nil, fmt.Errorf("capture requires windows")
}
