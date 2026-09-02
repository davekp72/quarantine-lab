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
	maxChangedFileEntries      = 2500
	maxPathResolvePerCapture   = 300
	maxFileHashesPerCapture    = 150
	maxUSNPathsForChangedFiles = 12000
)

// ChangedFiles builds file entries from USN and Sysmon sidecar JSON.
func ChangedFiles(usnRaw, sysmonRaw json.RawMessage, hashMaxMB, contentMaxKB int) (json.RawMessage, int, error) {
	defer BeginPathResolveBudget(maxPathResolvePerCapture)()

	if hashMaxMB <= 0 {
		hashMaxMB = 50
	}
	if contentMaxKB <= 0 {
		contentMaxKB = 51200
	}
	hashMax := int64(hashMaxMB) * 1024 * 1024
	contentMax := int64(contentMaxKB) * 1024

	pathKinds := map[string]string{}
	addPath := func(p, kind string) {
		p = normalizePath(p)
		if p == "" {
			return
		}
		if existing, ok := pathKinds[p]; ok {
			if kind == "removed" || (existing != "removed" && kind == "added") {
				pathKinds[p] = kind
			}
			return
		}
		pathKinds[p] = kind
	}

	if usnRaw != nil {
		var usn map[string]any
		if json.Unmarshal(usnRaw, &usn) == nil {
			if evs, ok := usn["events"].([]any); ok {
				seenRefs := map[string]bool{}
				for _, e := range evs {
					if len(seenRefs) >= maxUSNPathsForChangedFiles {
						break
					}
					em, ok := e.(map[string]any)
					if !ok {
						continue
					}
					name, _ := em["fileName"].(string)
					fileRef, _ := em["fileRef"].(string)
					dedupeKey := fileRef + "|" + name
					if dedupeKey != "|" {
						if seenRefs[dedupeKey] {
							continue
						}
						seenRefs[dedupeKey] = true
					}
					reasons, _ := em["reason"].([]any)
					kind := usnChangeKind(reasons)
					path, _ := em["path"].(string)
					if path == "" {
						path = usnEventPath(DefaultVolume(), name, fileRef)
					}
					addPath(path, kind)
				}
			}
		}
	}

	if sysmonRaw != nil {
		var sysmon map[string]any
		if json.Unmarshal(sysmonRaw, &sysmon) == nil {
			if evs, ok := sysmon["events"].([]any); ok {
				for _, e := range evs {
					em, ok := e.(map[string]any)
					if !ok {
						continue
					}
					typ, _ := em["t"].(string)
					target := stringField(em, "target")
					if target == "" {
						target = stringField(em, "targetFilename")
					}
					switch typ {
					case "FileCreate", "FileCreateStream":
						addPath(normalizePath(target), "added")
					case "FileDelete", "FileDeleteDetected":
						addPath(normalizePath(target), "removed")
					}
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
			"src":    "events",
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

func usnChangeKind(reasons []any) string {
	labels := map[string]bool{}
	for _, r := range reasons {
		if s, ok := r.(string); ok {
			labels[s] = true
		}
	}
	if labels["file_delete"] || labels["rename_old_name"] {
		return "removed"
	}
	if labels["file_create"] || labels["rename_new_name"] {
		return "added"
	}
	return "modified"
}

func resolveUsnPath(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if len(name) >= 2 && name[1] == ':' {
		return filepath.Clean(name)
	}
	if strings.HasPrefix(name, `\`) {
		return filepath.Clean(`C:` + name)
	}
	if strings.Contains(strings.ToLower(name), `\hosts`) || strings.EqualFold(name, "hosts") {
		return `C:\Windows\System32\drivers\etc\hosts`
	}
	return filepath.Clean(`C:\` + name)
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
