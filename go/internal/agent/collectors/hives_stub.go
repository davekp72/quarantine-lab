//go:build !windows

package collectors

import (
	"fmt"

	"github.com/quarantine-lab/quarantine/internal/agent/types"
)

func SaveRegistryHives(snapshotName, payloadUser string) (*types.HiveDump, error) {
	return nil, fmt.Errorf("hive dump requires windows")
}
