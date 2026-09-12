package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/quarantine-lab/quarantine/internal/evidence"
)

// ReadSnapshotFile reads file content from sidecar capture or snapshot disk.
func (a *App) ReadSnapshotFile(snapshotName, guestPath string) (map[string]any, error) {
	return a.readSnapshotFile(snapshotName, guestPath, true, true)
}

// readSnapshotFile loads a guest path for preview.
// allowDisk enables VDI only when the path is absent from the changed-files sidecar.
func (a *App) readSnapshotFile(snapshotName, guestPath string, allowAgent, allowDisk bool) (map[string]any, error) {
	max := a.filePreviewMaxBytes()
	var expectSize int64
	if a.Evidence != nil {
		if entry, ok := a.Evidence.FileSidecarEntry(snapshotName, guestPath); ok {
			if data, ok := evidence.FileSidecarContent(entry); ok {
				return filePreviewResult(guestPath, data, evidence.FileSidecarSize(entry), "sidecar", max), nil
			}
			expectSize = evidence.FileSidecarSize(entry)
			coding := ""
			if s, ok := entry["c"].(string); ok {
				coding = strings.ToLower(strings.TrimSpace(s))
			}
			if coding == "too_large" || expectSize > max {
				size := expectSize
				if size <= 0 {
					size = evidence.FileSidecarSize(entry)
				}
				return tooLargeFilePreview(guestPath, size, max), nil
			}
			if allowAgent {
				if data, ok := a.tryAgentFilePreview(guestPath, expectSize, max); ok {
					return filePreviewResult(guestPath, data, expectSize, "agent", max), nil
				}
			}
			reason := "sidecar_no_content"
			if coding == "access_denied" || coding == "missing" {
				reason = coding
			}
			msg := fmt.Sprintf(
				"Content not embedded in sidecar (%s).\n\nPath: %s\n\nRe-Preserve after raising content embed limits, or the guest denied read access.",
				reason, guestPath,
			)
			return map[string]any{
				"path":        guestPath,
				"size":        expectSize,
				"content":     msg,
				"unavailable": true,
				"reason":      reason,
				"source":      "sidecar-meta",
			}, nil
		}
		if !allowDisk {
			return map[string]any{
				"path":    guestPath,
				"content": "",
				"source":  "none",
			}, nil
		}
	} else if !allowDisk {
		return map[string]any{
			"path":    guestPath,
			"content": "",
			"source":  "none",
		}, nil
	}
	if a.Disk == nil {
		return nil, fmt.Errorf("disk reader unavailable")
	}
	data, info, err := a.Disk.ReadFile(snapshotName, guestPath, max)
	if err != nil {
		if isDiskFileNotFound(err) {
			return unavailableFilePreview(a.Evidence, snapshotName, guestPath, "deleted_before_snapshot"), nil
		}
		if isDiskFileTooLarge(err) {
			size := int64(0)
			if info != nil {
				size = info.Size
			}
			return tooLargeFilePreview(guestPath, size, max), nil
		}
		return nil, err
	}
	full := int64(len(data))
	if info != nil && info.Size > 0 {
		full = info.Size
	}
	return filePreviewResult(guestPath, data, full, "disk", max), nil
}

func previewHasContent(res map[string]any) bool {
	if res == nil {
		return false
	}
	if v, _ := res["unavailable"].(bool); v {
		return false
	}
	c, _ := res["content"].(string)
	return strings.TrimSpace(c) != ""
}

// DiffSnapshotFile reads From and To contents from sidecars only (no VDI).
func (a *App) DiffSnapshotFile(fromSnap, toSnap, guestPath string) (map[string]any, error) {
	max := a.filePreviewMaxBytes()
	var (
		fromRes, toRes map[string]any
		fromErr, toErr error
		wg             sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		fromRes, fromErr = a.readSnapshotFile(fromSnap, guestPath, false, false)
	}()
	go func() {
		defer wg.Done()
		toRes, toErr = a.readSnapshotFile(toSnap, guestPath, true, false)
	}()
	wg.Wait()

	if !previewHasContent(fromRes) && a.Evidence != nil {
		if entry, ok := a.Evidence.FileSidecarEntry(toSnap, guestPath); ok {
			if data, ok := evidence.FileSidecarBeforeContent(entry); ok {
				fromRes = filePreviewResult(guestPath, data, int64(len(data)), "sidecar-before", max)
				fromErr = nil
			}
		}
	}

	if fromErr != nil && toErr != nil {
		return nil, fmt.Errorf("from: %v; to: %v", fromErr, toErr)
	}

	out := map[string]any{
		"path":         guestPath,
		"fromSnapshot": fromSnap,
		"toSnapshot":   toSnap,
	}
	if fromRes != nil {
		out["fromContent"] = fromRes["content"]
		out["fromSize"] = fromRes["size"]
		out["fromSource"] = fromRes["source"]
		out["fromUnavailable"] = fromRes["unavailable"]
		out["fromTruncated"] = fromRes["truncated"]
	} else {
		out["fromContent"] = ""
		if fromErr != nil {
			out["fromError"] = fromErr.Error()
		}
	}
	if toRes != nil {
		out["toContent"] = toRes["content"]
		out["content"] = toRes["content"]
		out["size"] = toRes["size"]
		out["toSize"] = toRes["size"]
		out["toSource"] = toRes["source"]
		out["source"] = toRes["source"]
		out["unavailable"] = toRes["unavailable"]
		out["toUnavailable"] = toRes["unavailable"]
		out["truncated"] = toRes["truncated"]
		out["toTruncated"] = toRes["truncated"]
	} else {
		out["toContent"] = ""
		out["content"] = ""
		if toErr != nil {
			out["toError"] = toErr.Error()
		}
	}
	if fromErr != nil {
		out["fromError"] = fromErr.Error()
		if out["fromContent"] == nil {
			out["fromContent"] = ""
		}
	}
	if toErr != nil {
		out["toError"] = toErr.Error()
	}
	if !previewHasContent(fromRes) {
		if src, _ := out["fromSource"].(string); src == "none" || src == "sidecar-meta" || src == "" {
			out["fromContent"] = ""
			out["fromUnavailable"] = false
			out["fromNote"] = "Baseline content not in sidecar (re-Preserve to store before-state)."
		}
	}
	return out, nil
}

// tryAgentFilePreview reads a small guest file via the agent when the sidecar
// has size/metadata but no body. Rejects when live size disagrees with the sidecar.
func (a *App) tryAgentFilePreview(guestPath string, expectSize, max int64) ([]byte, bool) {
	if a == nil || a.Evidence == nil || a.Cfg == nil || !a.Cfg.Agent.Enabled {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	data, err := a.Evidence.ReadGuestFileBytes(ctx, guestPath, max)
	if err != nil || len(data) == 0 {
		return nil, false
	}
	if expectSize > 0 && int64(len(data)) != expectSize {
		if !(expectSize > max && int64(len(data)) == max) {
			return nil, false
		}
	}
	return data, true
}

// enrichChangedFilesBefore stores CleanSession bytes as bc/bd on modified Evidence rows.
// Never starts a CloneMedium flatten — only reads an existing RAW cache. Preserve stays
// sidecar-first; modified "before" diffs fill in only when baseline was already flattened.
func (a *App) enrichChangedFilesBefore(evidenceSnap string) {
	if a == nil || a.Disk == nil || a.Evidence == nil || a.Cfg == nil {
		return
	}
	baseline := strings.TrimSpace(a.Cfg.Manifest.SessionBaselineSnapshot)
	if baseline == "" {
		return
	}
	if !a.Disk.HasUsableFlattenCache(baseline) {
		a.logInfo(fmt.Sprintf(
			"Skip baseline before-content enrich for %s (no cached RAW for %s — avoids multi-GB CloneMedium)",
			evidenceSnap, baseline,
		))
		return
	}
	max := int64(a.Cfg.ContentMaxKBResolved()) * 1024
	snap := a.Cfg.ResolveSnapshotName(evidenceSnap)
	sc, err := a.Evidence.LoadSidecar(snap, "-changed-files.json")
	if err != nil {
		return
	}
	files, _ := sc["files"].([]any)
	updated := 0
	for i, item := range files {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		change, _ := entry["change"].(string)
		if !strings.EqualFold(change, "modified") {
			continue
		}
		if _, ok := evidence.FileSidecarBeforeContent(entry); ok {
			continue
		}
		p, _ := entry["p"].(string)
		if p == "" {
			p, _ = entry["path"].(string)
		}
		if strings.TrimSpace(p) == "" {
			continue
		}
		data, _, err := a.Disk.ReadFile(baseline, p, max)
		if err != nil || len(data) == 0 {
			continue
		}
		evidence.AttachSidecarBeforeContent(entry, data)
		files[i] = entry
		updated++
	}
	if updated == 0 {
		return
	}
	sc["files"] = files
	out, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		return
	}
	path := a.Cfg.SidecarPath(snap, "-changed-files.json")
	if err := os.WriteFile(path, out, 0o644); err != nil {
		a.logInfo("Baseline before-content enrich failed: " + err.Error())
		return
	}
	a.logInfo(fmt.Sprintf("Stored baseline content for %d modified file(s) from %s", updated, baseline))
}

// DiffSnapshotFileWails reads From+To contents for the Changed-files preview.
func (a *App) DiffSnapshotFileWails(fromSnap, toSnap, guestPath string) (map[string]any, error) {
	return a.DiffSnapshotFile(fromSnap, toSnap, guestPath)
}

// ReadSnapshotFileWails reads guest file for preview panel.
func (a *App) ReadSnapshotFileWails(snapshotName, guestPath string) (map[string]any, error) {
	// Prefer sidecar; only flatten when the path was never listed in changed-files.
	return a.readSnapshotFile(snapshotName, guestPath, true, true)
}
