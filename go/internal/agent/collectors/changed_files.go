package collectors

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	maxChangedFileEntries   = 4000
	maxFileHashesPerCapture = 150
	maxContentEmbedBytes    = 256 * 1024
)

type fileChange struct {
	path string
	kind string
	src  string
}

// ChangedFiles builds file entries from USN + Sysmon (create, delete, modify).
func ChangedFiles(usnRaw json.RawMessage, sysmonRaw json.RawMessage, hashMaxMB, contentMaxKB int) (json.RawMessage, int, error) {
	if hashMaxMB <= 0 {
		hashMaxMB = 50
	}
	if contentMaxKB <= 0 {
		contentMaxKB = 256
	}
	hashMax := int64(hashMaxMB) * 1024 * 1024
	contentMax := int64(contentMaxKB) * 1024
	if contentMax > maxContentEmbedBytes {
		contentMax = maxContentEmbedBytes
	}

	pathKinds := map[string]string{}
	pathSrc := map[string]string{}
	noise := map[string]int{}

	add := func(path, kind, src string) {
		path = normalizePath(path)
		if path == "" || isLeafOnlyPath(path) {
			return
		}
		if class := ClassifyFileNoise(path, filepath.Base(path)); class != "" {
			noise[class]++
			return
		}
		mergeFileChangeKind(pathKinds, path, kind)
		if existing, ok := pathSrc[path]; ok && existing != src {
			pathSrc[path] = "usn+sysmon"
		} else {
			pathSrc[path] = src
		}
	}

	if usnRaw != nil {
		var usn map[string]any
		if json.Unmarshal(usnRaw, &usn) == nil {
			if evs, ok := usn["events"].([]any); ok {
				for _, e := range evs {
					em, ok := e.(map[string]any)
					if !ok {
						continue
					}
					path := stringField(em, "path")
					if path == "" {
						path = stringField(em, "fileName")
					}
					kind := stringField(em, "change")
					if kind == "" {
						kind = usnChangeKind(reasonStringsFromEvent(em))
					}
					add(path, kind, "usn")
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
					add(target, kind, "sysmon")
				}
			}
		}
	}

	items := make([]fileChange, 0, len(pathKinds))
	for path, kind := range pathKinds {
		items = append(items, fileChange{path: path, kind: kind, src: pathSrc[path]})
	}
	sort.Slice(items, func(i, j int) bool {
		pi, pj := FilePriority(items[i].path), FilePriority(items[j].path)
		if pi != pj {
			return pi < pj
		}
		return strings.ToLower(items[i].path) < strings.ToLower(items[j].path)
	})

	truncated := false
	if len(items) > maxChangedFileEntries {
		// Never drop priority 0–2 (System32/etc, Program Files, executables).
		cut := maxChangedFileEntries
		for cut < len(items) && FilePriority(items[cut].path) <= 2 {
			cut++
		}
		if cut < len(items) {
			truncated = true
			items = items[:cut]
		}
	}

	var files []map[string]any
	hashed := 0
	for _, item := range items {
		info, err := os.Stat(item.path)
		exists := err == nil && info != nil && !info.IsDir()
		kind := reconcileKindWithDisk(item.kind, exists)
		entry := map[string]any{
			"p":      item.path,
			"change": kind,
			"src":    item.src,
		}
		if err != nil || info.IsDir() {
			files = append(files, entry)
			continue
		}
		entry["s"] = info.Size()
		entry["m"] = info.ModTime().UTC().Format("2006-01-02T15:04:05Z")
		wantHash := FilePriority(item.path) <= 2 && hashed < maxFileHashesPerCapture && info.Size() <= hashMax
		if wantHash {
			if h, err := hashFile(item.path); err == nil {
				entry["h"] = h
				hashed++
			}
			if info.Size() <= contentMax && FilePriority(item.path) <= 1 {
				if c := fileContentPayload(item.path, contentMax); c != nil {
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
		"pathCount": len(pathKinds),
		"files":     files,
		"noise":     noise,
	}
	if truncated {
		out["truncated"] = true
	}
	payload, err := json.Marshal(out)
	return payload, len(files), err
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
	if strings.HasPrefix(p, `\\?\`) {
		p = p[4:]
	}
	return filepath.Clean(p)
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func fileContentPayload(path string, max int64) map[string]any {
	info, err := os.Stat(path)
	if err != nil {
		return map[string]any{"c": "access_denied"}
	}
	if info.Size() > max {
		return map[string]any{"c": "too_large"}
	}
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
