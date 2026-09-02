//go:build windows

package capture

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/quarantine-lab/quarantine/internal/agent/collectors"
	"github.com/quarantine-lab/quarantine/internal/agent/types"
)

// Run executes a capture request on the guest.
func Run(req types.CaptureRequest, cfg types.AgentConfig) (*types.CaptureResponse, error) {
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "baseline"
	}
	payloadUser := strings.TrimSpace(req.PayloadUser)
	if payloadUser == "" {
		payloadUser = cfg.PayloadUser
	}

	resp := &types.CaptureResponse{
		Snapshot:     req.Snapshot,
		CapturedAt:   time.Now().UTC().Format(time.RFC3339),
		ComputerName: os.Getenv("COMPUTERNAME"),
		Warnings:     []string{},
	}

	var baselineAt string
	var baselineRaw json.RawMessage

	if mode == "baseline" {
		bl, err := collectors.Baseline(collectors.DefaultVolume())
		if err != nil {
			return nil, fmt.Errorf("USN baseline: %w", err)
		}
		baselineRaw = bl
		resp.Baseline = bl
		var b map[string]any
		if json.Unmarshal(bl, &b) == nil {
			baselineAt, _ = b["recordedAt"].(string)
		}
		resp.USN = collectors.BaselineMarker("Baseline snapshot — USN delta starts after this point.", bl)
		resp.Sysmon = collectors.BaselineMarker("Baseline snapshot — Sysmon events start after this point.", bl)
		resp.ServiceInstalls = collectors.BaselineMarker("Baseline snapshot — service install events start after this point.", bl)
		empty, _ := json.Marshal(map[string]any{"fileCount": 0, "files": []any{}})
		resp.ChangedFiles = empty
	} else {
		if len(req.Baseline) == 0 {
			return nil, fmt.Errorf("evidence capture requires baseline JSON")
		}
		baselineRaw = req.Baseline
		var b map[string]any
		if json.Unmarshal(baselineRaw, &b) == nil {
			baselineAt, _ = b["recordedAt"].(string)
		}
		if baselineAt == "" {
			baselineAt = req.BaselineAt
		}

		usn, usnCount, err := collectors.USNDelta(baselineRaw, 50000)
		if err != nil {
			resp.Warnings = append(resp.Warnings, "usn: "+err.Error())
			resp.USN = collectors.BaselineMarker("USN delta unavailable: "+err.Error(), baselineRaw)
		} else {
			resp.USN = usn
			resp.Stats.USNEvents = usnCount
		}

		sysmonLog := cfg.SysmonLog
		if sysmonLog == "" {
			sysmonLog = `Microsoft-Windows-Sysmon/Operational`
		}
		sysmon, sysCount, err := collectors.SysmonEvents(sysmonLog, baselineAt, 5000)
		if err != nil {
			resp.Warnings = append(resp.Warnings, "sysmon: "+err.Error())
		}
		resp.Sysmon = sysmon
		resp.Stats.SysmonEvents = sysCount

		svc, svcCount, err := collectors.ServiceInstallEvents(baselineAt, 500)
		if err != nil {
			resp.Warnings = append(resp.Warnings, "service installs: "+err.Error())
		}
		resp.ServiceInstalls = svc
		resp.Stats.ServiceInstallEvents = svcCount

		changed, fileCount, err := collectors.ChangedFiles(resp.USN, sysmon, req.HashMaxMB, req.ContentMaxKB)
		if err != nil {
			resp.Warnings = append(resp.Warnings, "changed files: "+err.Error())
		} else {
			resp.ChangedFiles = changed
			resp.Stats.ChangedFiles = fileCount
		}
	}

	hklm, err := collectors.ExportHKLM()
	if err != nil {
		resp.Warnings = append(resp.Warnings, "hklm: "+err.Error())
	} else {
		resp.Registry.HKLM = hklm
		resp.Stats.HKLMEntries = len(hklm)
	}

	hkcu, sid, user, err := collectors.ExportHKCU(payloadUser)
	if err != nil {
		resp.Warnings = append(resp.Warnings, "hkcu: "+err.Error())
		resp.Registry.Warnings = append(resp.Registry.Warnings, err.Error())
	} else {
		resp.Registry.HKCU = hkcu
		resp.Registry.SID = sid
		resp.Registry.UserName = user
		resp.Stats.HKCUEntries = len(hkcu)
	}

	return resp, nil
}
