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
	maxFileHashesPerCapture = 500
	// Absolute ceilings (request values are clamped to these).
	maxContentEmbedBytes = 64 * 1024 * 1024
	maxTotalEmbedBytes   = 512 * 1024 * 1024 // agent HTTP decode limit
	defaultContentMaxKB  = 51200             // 50 MiB
	defaultHashMaxMB     = 100
	defaultTotalEmbedMB  = 256
)

type fileChange struct {
	path string
	kind string
	src  string
}

// ChangedFiles builds file entries from USN + Sysmon (create, delete, modify).
func ChangedFiles(usnRaw json.RawMessage, sysmonRaw json.RawMessage, hashMaxMB, contentMaxKB, totalEmbedMaxMB int) (json.RawMessage, int, error) {
	if hashMaxMB <= 0 {
		hashMaxMB = defaultHashMaxMB
	}
	if contentMaxKB <= 0 {
		contentMaxKB = defaultContentMaxKB
	}
	if totalEmbedMaxMB <= 0 {
		totalEmbedMaxMB = defaultTotalEmbedMB
	}
	hashMax := int64(hashMaxMB) * 1024 * 1024
	contentMax := int64(contentMaxKB) * 1024
	if contentMax > maxContentEmbedBytes {
		contentMax = maxContentEmbedBytes
	}
	totalBudget := int64(totalEmbedMaxMB) * 1024 * 1024
	if totalBudget > maxTotalEmbedBytes {
		totalBudget = maxTotalEmbedBytes
	}

	pathKinds := map[string]string{}
	pathSrc := map[string]string{}
	pathNoise := map[string]string{}
	noise := map[string]int{}

	add := func(path, kind, src string) {
		path = normalizePath(path)
		if path == "" || isLeafOnlyPath(path) {
			return
		}
		if class := ClassifyFileNoise(path, filepath.Base(path)); class != "" {
			noise[class]++
			pathNoise[path] = class
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
		// Signal paths first so truncation keeps them; noise last.
		ni, nj := pathNoise[items[i].path] != "", pathNoise[items[j].path] != ""
		if ni != nj {
			return !ni && nj
		}
		pi, pj := FilePriority(items[i].path), FilePriority(items[j].path)
		if pi != pj {
			return pi < pj
		}
		return strings.ToLower(items[i].path) < strings.ToLower(items[j].path)
	})

	truncated := false
	if len(items) > maxChangedFileEntries {
		cut := maxChangedFileEntries
		for cut < len(items) && pathNoise[items[cut].path] == "" && FilePriority(items[cut].path) <= 2 {
			cut++
		}
		if cut < len(items) {
			truncated = true
			items = items[:cut]
		}
	}

	var files []map[string]any
	hashed := 0
	var embedBytes int64
	for _, item := range items {
		info, err := os.Stat(item.path)
		exists := err == nil && info != nil && !info.IsDir()
		kind := reconcileKindWithDisk(item.kind, exists)
		entry := map[string]any{
			"p":      item.path,
			"change": kind,
			"src":    item.src,
		}
		if nc := pathNoise[item.path]; nc != "" {
			entry["noise"] = nc
		}
		if err != nil || info.IsDir() {
			files = append(files, entry)
			continue
		}
		entry["s"] = info.Size()
		entry["m"] = info.ModTime().UTC().Format("2006-01-02T15:04:05Z")
		// Skip hash/embed for noise — keep sidecar small; UI can still list them.
		if pathNoise[item.path] != "" {
			files = append(files, entry)
			continue
		}
		wantHash := FilePriority(item.path) <= 2 && hashed < maxFileHashesPerCapture && info.Size() <= hashMax
		if wantHash {
			if h, err := hashFile(item.path); err == nil {
				entry["h"] = h
				hashed++
			}
		}
		if info.Size() <= contentMax && embedBytes+info.Size() <= totalBudget {
			if c := fileContentPayload(item.path, contentMax); c != nil {
				if v, ok := c["c"]; ok {
					entry["c"] = v
				}
				if v, ok := c["d"]; ok {
					entry["d"] = v
					embedBytes += info.Size()
				}
			}
		} else if info.Size() > contentMax {
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
