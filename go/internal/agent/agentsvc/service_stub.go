//go:build !windows

package agentsvc

import (
	"fmt"

	"github.com/quarantine-lab/quarantine/internal/agent/types"
)

const ServiceName = "QuarantineLabAgent"

func RunConsole(token string, cfg types.AgentConfig) error {
	return fmt.Errorf("quarantine-agent requires windows")
}

func RunService(token string, cfg types.AgentConfig) error {
	return fmt.Errorf("quarantine-agent requires windows")
}

func Install(exePath, token string, cfg types.AgentConfig) error {
	return fmt.Errorf("quarantine-agent requires windows")
}

func Uninstall() error {
	return fmt.Errorf("quarantine-agent requires windows")
}

func LoadConfig() (types.AgentConfig, error) {
	return types.AgentConfig{}, fmt.Errorf("quarantine-agent requires windows")
}

func LoadToken(path string) (string, error) {
	return "", fmt.Errorf("quarantine-agent requires windows")
}

func IsWindowsService() (bool, error) {
	return false, nil
}
