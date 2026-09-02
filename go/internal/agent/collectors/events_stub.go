//go:build !windows

package collectors

import (
	"encoding/json"
	"fmt"
)

func SysmonEvents(logName, baselineAt string, maxEvents int) (json.RawMessage, int, error) {
	return nil, 0, fmt.Errorf("sysmon collector requires windows")
}

func ServiceInstallEvents(baselineAt string, maxEvents int) (json.RawMessage, int, error) {
	return nil, 0, fmt.Errorf("service install collector requires windows")
}
