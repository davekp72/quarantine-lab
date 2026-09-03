package collectors

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	maxChangedFileEntries    = 2500
	maxFileHashesPerCapture  = 150
)

// ChangedFiles builds file entries from Sysmon file events (create, delete, modify).
func ChangedFiles(_ json.RawMessage, sysmonRaw json.RawMessage, hashMaxMB, contentMaxKB int) (json.RawMessage, int, error) {
	if hashMaxMB <= 0 {
		hashMaxMB = 50
	}
	if contentMaxKB <= 0 {
		contentMaxKB = 51200
	}
	hashMax := int64(hashMaxMB) * 1024 * 1024
	contentMax := int64(contentMaxKB) * 1024

	pathKinds := map[string]string{}

	if sysmonRaw != nil {
		var sysmon map[string]any
		if json.Unmarshal(sysmonRaw, &sysmon) == nil {
			if evs, ok := sysmon["events"].([]any); ok {
				for _, e := range evs {
					em, ok := e.(map[string]any)
					if !ok {
						continue
					}
					eid, _ := em["eid"].(float64)
					typ, _ := em["t"].(string)
					kind, isFile := SysmonFileChangeKind(int(eid), typ)
					if !isFile {
						continue
					}
					target := stringField(em, "target")
					if target == "" {
						target = stringField(em, "targetFilename")
					}
					mergeFileChangeKind(pathKinds, target, kind)
				}
			}
		}
	}

	var files []map[string]any
	hashed := 0
	truncated := false
	for path, kind := range pathKinds {
		if len(files) >= maxChangedFileEntries {
			truncated = true
			break
		}
		entry := map[string]any{
			"p":      path,
			"change": kind,
			"src":    "sysmon",
		}
		if isLeafOnlyUSNPath(path) {
			continue
		}
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			files = append(files, entry)
			continue
		}
		entry["s"] = info.Size()
		entry["m"] = info.ModTime().UTC().Format("2006-01-02T15:04:05Z")
		if info.Size() <= hashMax && hashed < maxFileHashesPerCapture {
			if h, err := hashFile(path); err == nil {
				entry["h"] = h
				hashed++
			}
			if info.Size() <= contentMax {
				if c := fileContentPayload(path, contentMax); c != nil {
					if v, ok := c["c"]; ok {
						entry["c"] = v
					}
					if v, ok := c["d"]; ok {
						entry["d"] = v
					}
				}
			}
		} else if info.Size() > hashMax {
			entry["c"] = "too_large"
		}
		files = append(files, entry)
	}

	out := map[string]any{
		"fileCount": len(files),
		"files":     files,
	}
	if truncated {
		out["truncated"] = true
		out["pathCount"] = len(pathKinds)
	}
	payload, err := json.Marshal(out)
	return payload, len(files), err
}

func isLeafOnlyUSNPath(p string) bool {
	p = normalizePath(p)
	if len(p) < 4 || p[1] != ':' {
		return false
	}
	rest := strings.TrimPrefix(p, p[:3])
	return rest != "" && !strings.Contains(rest, `\`)
}

func stringField(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if strings.HasPrefix(p, `\??\`) {
		p = p[4:]
	}
	return filepath.Clean(p)
}

func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:]), nil
}

func fileContentPayload(path string, max int64) map[string]any {
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string]any{"c": "access_denied"}
	}
	if int64(len(data)) > max {
		return map[string]any{"c": "too_large"}
	}
	for _, b := range data {
		if b == 0 {
			return map[string]any{"c": "base64", "d": base64.StdEncoding.EncodeToString(data)}
		}
	}
	if utf8.Valid(data) {
		text := string(data)
		bad := 0
		for _, ch := range text {
			if ch < 9 || (ch > 13 && ch < 32) {
				bad++
			}
		}
		if len(text) == 0 || float64(bad)/float64(maxInt(len(text), 1)) < 0.05 {
			return map[string]any{"c": "text", "d": text}
		}
	}
	return map[string]any{"c": "base64", "d": base64.StdEncoding.EncodeToString(data)}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
