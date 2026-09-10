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

	dumpHives := func() error {
		dump, err := collectors.SaveRegistryHives(req.Snapshot, payloadUser)
		if err != nil {
			return fmt.Errorf("hive dump: %w", err)
		}
		if dump == nil || len(dump.Files) == 0 {
			return fmt.Errorf("hive dump produced no files")
		}
		resp.Hives = dump
		resp.Warnings = append(resp.Warnings, dump.Warnings...)
		if sid, user, idErr := collectors.PayloadIdentity(payloadUser); idErr != nil {
			resp.Warnings = append(resp.Warnings, "payload identity: "+idErr.Error())
			resp.Registry.Warnings = append(resp.Registry.Warnings, idErr.Error())
		} else {
			resp.Registry.SID = sid
			resp.Registry.UserName = user
		}
		return nil
	}

	if mode == "baseline" {
		// Write hives first, then freeze USN so restore+evidence does not
		// treat capture artifacts as session changes.
		if err := dumpHives(); err != nil {
			return nil, err
		}
		bl, err := collectors.Baseline(collectors.DefaultVolume())
		if err != nil {
			return nil, fmt.Errorf("USN baseline: %w", err)
		}
		resp.Baseline = bl
		resp.USN = collectors.BaselineMarker("Baseline snapshot — USN delta starts after this point.", bl)
		resp.Sysmon = collectors.BaselineMarker("Baseline snapshot — Sysmon events start after this point.", bl)
		resp.ServiceInstalls = collectors.BaselineMarker("Baseline snapshot — service install events start after this point.", bl)
		empty, _ := json.Marshal(map[string]any{"fileCount": 0, "files": []any{}})
		resp.ChangedFiles = empty
		return resp, nil
	}

	if len(req.Baseline) == 0 {
		return nil, fmt.Errorf("evidence capture requires baseline JSON")
	}
	baselineRaw := req.Baseline
	baselineAt := req.BaselineAt
	var b map[string]any
	if json.Unmarshal(baselineRaw, &b) == nil {
		if v, _ := b["recordedAt"].(string); v != "" {
			baselineAt = v
		}
	}

	done := collectors.BeginPathResolveBudget(4000)
	defer done()

	usn, usnCount, err := collectors.USNDelta(baselineRaw, 20000)
	if err != nil {
		resp.Warnings = append(resp.Warnings, "usn: "+err.Error())
		resp.USN = collectors.BaselineMarker("USN delta unavailable: "+err.Error(), baselineRaw)
	} else {
		resp.USN = usn
		resp.Stats.USNEvents = usnCount
		appendJSONWarnings(resp, usn)
	}

	sysmonLog := cfg.SysmonLog
	if sysmonLog == "" {
		sysmonLog = `Microsoft-Windows-Sysmon/Operational`
	}
	sysmon, sysCount, err := collectors.SysmonEvents(sysmonLog, baselineAt, 20000)
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

	if err := dumpHives(); err != nil {
		return nil, err
	}
	return resp, nil
}

func appendJSONWarnings(resp *types.CaptureResponse, raw json.RawMessage) {
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return
	}
	switch w := doc["warnings"].(type) {
	case []any:
		for _, item := range w {
			if s, ok := item.(string); ok && s != "" {
				resp.Warnings = append(resp.Warnings, s)
			}
		}
	case []string:
		resp.Warnings = append(resp.Warnings, w...)
	}
}
