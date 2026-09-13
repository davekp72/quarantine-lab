package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quarantine-lab/quarantine/internal/cases"
	"github.com/quarantine-lab/quarantine/internal/diff"
	"github.com/quarantine-lab/quarantine/internal/evidence"
)

func (a *App) caseBodyCap() int64 {
	preview := a.filePreviewMaxBytes()
	if a.Cfg == nil {
		return preview
	}
	embed := int64(a.Cfg.ContentMaxKBResolved()) * 1024
	if embed > 0 && embed < preview {
		return embed
	}
	return preview
}

func (a *App) saveCompareCase(result *diff.Result, excludeNoise bool) (*cases.Meta, error) {
	if a == nil || a.Cases == nil || result == nil || a.Cfg == nil {
		return nil, fmt.Errorf("case store unavailable")
	}
	to := result.Meta.ToSnapshot
	from := result.Meta.FromSnapshot
	max := a.caseBodyCap()
	started := time.Now()
	var toIdx, fromIdx map[string]map[string]any
	if a.Evidence != nil {
		toIdx = a.Evidence.FileSidecarIndex(to)
		fromIdx = a.Evidence.FileSidecarIndex(from)
	}
	meta, err := a.Cases.Save(cases.SaveRequest{
		Result:        result,
		ExcludeNoise:  excludeNoise,
		ToNetworkDir:  a.Cfg.SidecarPath(to, "-network"),
		MaxBodyBytes:  max,
		LoadFrom:      a.caseLoadFromIndex(fromIdx, toIdx, max),
		LoadTo:        a.caseLoadToIndex(toIdx, max),
		NoiseDomains:  a.Cfg.NoiseDomains(),
		NoiseFiles:    a.Cfg.NoiseFiles(),
		NoiseRegistry: a.Cfg.NoiseRegistry(),
	})
	if err != nil {
		a.logWarn("Save compare case: " + err.Error())
		return nil, err
	}
	a.logInfo(fmt.Sprintf("Case saved: %s (%d file bodies, network=%v, %s)", meta.ID, meta.FileBodies, meta.NetworkCopied, time.Since(started).Round(time.Millisecond)))
	return meta, nil
}

// SaveCaseWails archives the last live Compare. Snapshots must still exist for sidecar/network copy.
func (a *App) SaveCaseWails(excludeNoise bool) (map[string]any, error) {
	if a == nil {
		return nil, fmt.Errorf("app unavailable")
	}
	if strings.TrimSpace(a.ActiveCase) != "" {
		return nil, fmt.Errorf("already reviewing a saved case")
	}
	if a.LastResult == nil {
		return nil, fmt.Errorf("compare snapshots first")
	}
	meta, err := a.saveCompareCase(a.LastResult, excludeNoise)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"id":            meta.ID,
		"fromSnapshot":  meta.FromSnapshot,
		"toSnapshot":    meta.ToSnapshot,
		"excludeNoise":  meta.ExcludeNoise,
		"createdAt":     meta.CreatedAt,
		"networkCopied": meta.NetworkCopied,
		"fileBodies":    meta.FileBodies,
	}, nil
}

func clipBody(data []byte, max int64, reasonIfEmpty string) cases.Body {
	if len(data) == 0 {
		return cases.Body{Unavailable: true, Reason: reasonIfEmpty}
	}
	b := cases.Body{Data: data}
	if max > 0 && int64(len(data)) > max {
		b.Data = data[:max]
		b.Truncated = true
	}
	return b
}

func (a *App) caseLoadToIndex(toIdx map[string]map[string]any, max int64) func(string) cases.Body {
	return func(guestPath string) cases.Body {
		return bodyFromSidecarIndex(toIdx, guestPath, max, false)
	}
}

func (a *App) caseLoadFromIndex(fromIdx, toIdx map[string]map[string]any, max int64) func(string) cases.Body {
	return func(guestPath string) cases.Body {
		if entry, ok := evidence.FileSidecarLookup(toIdx, guestPath); ok {
			if data, ok := evidence.FileSidecarBeforeContent(entry); ok {
				return clipBody(data, max, "")
			}
		}
		return bodyFromSidecarIndex(fromIdx, guestPath, max, false)
	}
}

// bodyFromSidecarIndex reads Preserve embeds only. VDI/NTFS at Compare time
// (open chain per path) is what made Compare feel slow after case packs landed.
func bodyFromSidecarIndex(index map[string]map[string]any, guestPath string, max int64, preferBefore bool) cases.Body {
	entry, ok := evidence.FileSidecarLookup(index, guestPath)
	if !ok {
		return cases.Body{Unavailable: true, Reason: "no_sidecar"}
	}
	if preferBefore {
		if data, ok := evidence.FileSidecarBeforeContent(entry); ok {
			return clipBody(data, max, "")
		}
	}
	if data, ok := evidence.FileSidecarContent(entry); ok {
		return clipBody(data, max, "")
	}
	coding := ""
	if s, ok := entry["c"].(string); ok {
		coding = strings.ToLower(strings.TrimSpace(s))
	}
	size := evidence.FileSidecarSize(entry)
	if coding == "too_large" || (size > max && max > 0) {
		return cases.Body{Unavailable: true, Reason: "too_large"}
	}
	return cases.Body{Unavailable: true, Reason: "no_content"}
}

// ListCasesWails lists saved compare packs newest first.
func (a *App) ListCasesWails() ([]map[string]any, error) {
	if a.Cases == nil {
		return []map[string]any{}, nil
	}
	list, err := a.Cases.List()
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(list))
	for _, m := range list {
		out = append(out, map[string]any{
			"id":            m.ID,
			"fromSnapshot":  m.FromSnapshot,
			"toSnapshot":    m.ToSnapshot,
			"fromCaptured":  m.FromCaptured,
			"toCaptured":    m.ToCaptured,
			"excludeNoise":  m.ExcludeNoise,
			"createdAt":     m.CreatedAt,
			"networkCopied": m.NetworkCopied,
			"fileBodies":    m.FileBodies,
			"bytes":         m.Bytes,
		})
	}
	return out, nil
}

// LoadCaseWails opens an archived compare (no snapshots required).
func (a *App) LoadCaseWails(id string) (map[string]any, error) {
	if a.Cases == nil {
		return nil, fmt.Errorf("case store unavailable")
	}
	raw, meta, err := a.Cases.LoadCompare(id)
	if err != nil {
		return nil, err
	}
	a.ActiveCase = meta.ID
	a.LastDiffPath = a.Cases.ComparePath(meta.ID)
	return map[string]any{
		"id":           meta.ID,
		"fromSnapshot": meta.FromSnapshot,
		"toSnapshot":   meta.ToSnapshot,
		"excludeNoise": meta.ExcludeNoise,
		"createdAt":    meta.CreatedAt,
		"compareJSON":  string(raw),
	}, nil
}

// DeleteCaseWails removes a saved compare pack. Does not touch VM snapshots.
func (a *App) DeleteCaseWails(id string) (string, error) {
	if a.Cases == nil {
		return "", fmt.Errorf("case store unavailable")
	}
	id = strings.TrimSpace(id)
	if a.ActiveCase == id {
		a.ActiveCase = ""
	}
	if err := a.Cases.Delete(id); err != nil {
		return "", err
	}
	a.logInfo("Deleted case " + id)
	return "Deleted case " + id, nil
}

// ReadCaseFileWails returns archived file bytes (never flattens a disk).
func (a *App) ReadCaseFileWails(caseID, guestPath string) (map[string]any, error) {
	if a.Cases == nil {
		return nil, fmt.Errorf("case store unavailable")
	}
	max := a.filePreviewMaxBytes()
	from, to, ent, err := a.Cases.ReadBodies(caseID, guestPath)
	if err != nil {
		return map[string]any{
			"path":        guestPath,
			"content":     err.Error(),
			"unavailable": true,
			"source":      "case",
		}, nil
	}
	data := to
	reason := ent.ToReason
	unavail := ent.ToUnavail
	truncated := ent.ToTruncated
	if len(data) == 0 {
		data = from
		reason = ent.FromReason
		unavail = ent.FromUnavail
		truncated = ent.FromTruncated
	}
	if reason == "too_large" {
		return tooLargeFilePreview(guestPath, 0, max), nil
	}
	if len(data) == 0 {
		msg := reason
		if msg == "" {
			msg = "Content was not archived for this path."
		}
		return map[string]any{
			"path":        guestPath,
			"content":     msg,
			"unavailable": true,
			"source":      "case",
			"reason":      reason,
		}, nil
	}
	res := filePreviewResult(guestPath, data, int64(len(data)), "case", max)
	if truncated {
		res["truncated"] = true
	}
	if unavail {
		res["unavailable"] = true
	}
	return res, nil
}

// DiffCaseFileWails returns archived from/to bytes for a modified path.
func (a *App) DiffCaseFileWails(caseID, guestPath string) (map[string]any, error) {
	if a.Cases == nil {
		return nil, fmt.Errorf("case store unavailable")
	}
	max := a.filePreviewMaxBytes()
	from, to, ent, err := a.Cases.ReadBodies(caseID, guestPath)
	if err != nil {
		return map[string]any{
			"path":         guestPath,
			"fromContent":  "",
			"toContent":    "",
			"content":      "",
			"fromError":    err.Error(),
			"toError":      err.Error(),
			"fromSnapshot": "",
			"toSnapshot":   "",
		}, nil
	}
	fromRes := filePreviewResult(guestPath, from, int64(len(from)), "case", max)
	toRes := filePreviewResult(guestPath, to, int64(len(to)), "case", max)
	if ent.FromReason == "too_large" {
		fromRes = tooLargeFilePreview(guestPath, 0, max)
	} else if len(from) == 0 && ent.FromUnavail {
		fromRes["unavailable"] = true
		fromRes["content"] = ent.FromReason
	}
	if ent.ToReason == "too_large" {
		toRes = tooLargeFilePreview(guestPath, 0, max)
	} else if len(to) == 0 && ent.ToUnavail {
		toRes["unavailable"] = true
		toRes["content"] = ent.ToReason
	}
	if ent.FromTruncated {
		fromRes["truncated"] = true
	}
	if ent.ToTruncated {
		toRes["truncated"] = true
	}
	out := map[string]any{
		"path":            guestPath,
		"fromSnapshot":    "",
		"toSnapshot":      "",
		"fromContent":     fromRes["content"],
		"toContent":       toRes["content"],
		"content":         toRes["content"],
		"fromSize":        fromRes["size"],
		"toSize":          toRes["size"],
		"size":            toRes["size"],
		"fromSource":      "case",
		"toSource":        "case",
		"source":          "case",
		"fromUnavailable": fromRes["unavailable"],
		"toUnavailable":   toRes["unavailable"],
		"unavailable":     toRes["unavailable"],
		"fromTruncated":   fromRes["truncated"],
		"toTruncated":     toRes["truncated"],
		"truncated":       toRes["truncated"],
	}
	return out, nil
}

func (a *App) casePcapPath() (string, error) {
	if a == nil || a.Cases == nil || strings.TrimSpace(a.ActiveCase) == "" {
		return "", fmt.Errorf("no active case")
	}
	dir := a.Cases.NetworkDir(a.ActiveCase)
	pcap := filepath.Join(dir, "capture.pcap")
	if _, err := os.Stat(pcap); err != nil {
		alt := filepath.Join(dir, "capture.pcapng")
		if _, err2 := os.Stat(alt); err2 == nil {
			return alt, nil
		}
		return "", fmt.Errorf("no capture.pcap in case %s", a.ActiveCase)
	}
	return pcap, nil
}

func (a *App) caseNetworkDir() string {
	if a == nil || a.Cases == nil || strings.TrimSpace(a.ActiveCase) == "" {
		return ""
	}
	return a.Cases.NetworkDir(a.ActiveCase)
}

// ClearActiveCaseWails leaves review mode so file/HTTP/PCAP use live snapshots again.
func (a *App) ClearActiveCaseWails() {
	if a != nil {
		a.ActiveCase = ""
	}
}
