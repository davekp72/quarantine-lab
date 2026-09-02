//go:build !windows

package collectors

import (
	"fmt"

	"github.com/quarantine-lab/quarantine/internal/agent/types"
)

func ExportHKLM() ([]types.RegistryEntry, error) {
	return nil, fmt.Errorf("registry collector requires windows")
}

func ExportHKCU(payloadUser string) ([]types.RegistryEntry, string, string, error) {
	return nil, "", "", fmt.Errorf("registry collector requires windows")
}

func PayloadSessionActive(payloadUser string) (bool, string) {
	return false, ""
}
