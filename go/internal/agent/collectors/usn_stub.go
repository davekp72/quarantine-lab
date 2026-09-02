//go:build !windows

package collectors

import (
	"encoding/json"
	"fmt"
)

func DefaultVolume() string { return `C:` }

func USNAvailable() bool { return false }

func Baseline(volume string) (json.RawMessage, error) {
	return nil, fmt.Errorf("USN collector requires windows")
}

func USNDelta(baselineRaw json.RawMessage, maxEvents int) (json.RawMessage, int, error) {
	return nil, 0, fmt.Errorf("USN collector requires windows")
}

func BaselineMarker(message string, baselineRaw json.RawMessage) json.RawMessage {
	m := map[string]any{
		"available": false, "message": message, "events": []any{},
	}
	raw, _ := json.Marshal(m)
	return raw
}
