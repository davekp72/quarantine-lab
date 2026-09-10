package collectors

import (
	"sort"
	"strings"
	"time"
)

const maxUSNSidecarEvents = 4000

// FinalizeUSNEvents drops pre-baseline / close-only noise, resolves paths, and
// compact-merges by path so the sidecar stays small and diffs stay fast.
func FinalizeUSNEvents(volume string, events []map[string]any, startUsn uint64, timeFloor time.Time) (kept []map[string]any, noise map[string]int, skippedBeforeStart int) {
	noise = map[string]int{}
	merged := map[string]map[string]any{}

	for _, ev := range events {
		if ev == nil {
			continue
		}
		usn := usnFromEvent(ev)
		if startUsn > 0 && usn > 0 && usn < startUsn {
			skippedBeforeStart++
			continue
		}
		if !timeFloor.IsZero() {
			if ts, ok := ev["timestamp"].(string); ok && ts != "" {
				if t, err := time.Parse(time.RFC3339, ts); err == nil && t.Before(timeFloor) {
					continue
				}
			}
		}
		reasons := reasonStringsFromEvent(ev)
		if isCloseOnlyReason(reasons, reasonCodeFromEvent(ev)) {
			noise["close_only"]++
			continue
		}

		fileName, _ := ev["fileName"].(string)
		if class := ClassifyFileNoise("", fileName); class != "" {
			noise[class]++
			continue
		}

		fileRef, _ := ev["fileRef"].(string)
		parentRef, _ := ev["parentRef"].(string)
		path, _ := ev["path"].(string)
		if path == "" {
			path = usnEventPath(volume, fileName, fileRef, parentRef)
		}
		if isLeafOnlyPath(path) {
			path = ""
		}
		if path != "" {
			ev["path"] = path
		}

		if path == "" {
			noise["unresolved"]++
			continue
		}

		class := ClassifyFileNoise(path, fileName)
		if class != "" {
			noise[class]++
			continue
		}

		key := strings.ToLower(path)
		kind := usnChangeKind(reasons)
		if existing, ok := merged[key]; ok {
			existing["change"] = netUSNKind(stringField(existing, "change"), kind)
			existing["reason"] = mergeReasonLists(reasonStringsFromEvent(existing), reasons)
			if usn >= usnFromEvent(existing) {
				existing["usn"] = ev["usn"]
				existing["reasonCode"] = ev["reasonCode"]
			}
			if path != "" {
				existing["path"] = path
			}
			continue
		}
		out := map[string]any{
			"usn":        ev["usn"],
			"fileName":   fileName,
			"fileRef":    fileRef,
			"reason":     reasons,
			"reasonCode": ev["reasonCode"],
			"change":     kind,
		}
		if path != "" {
			out["path"] = path
		}
		if parentRef != "" {
			out["parentRef"] = parentRef
		}
		if ts, ok := ev["timestamp"]; ok {
			out["timestamp"] = ts
		}
		merged[key] = out
	}

	kept = make([]map[string]any, 0, len(merged))
	for _, ev := range merged {
		kept = append(kept, ev)
	}
	sort.Slice(kept, func(i, j int) bool {
		pi, _ := kept[i]["path"].(string)
		pj, _ := kept[j]["path"].(string)
		if FilePriority(pi) != FilePriority(pj) {
			return FilePriority(pi) < FilePriority(pj)
		}
		return strings.ToLower(pi) < strings.ToLower(pj)
	})
	if len(kept) > maxUSNSidecarEvents {
		noise["truncated_sidecar"] = len(kept) - maxUSNSidecarEvents
		kept = kept[:maxUSNSidecarEvents]
	}
	return kept, noise, skippedBeforeStart
}

func usnChangeKind(reasons []string) string {
	hasDelete, hasCreate := false, false
	for _, r := range reasons {
		n := strings.ToLower(strings.ReplaceAll(r, " ", "_"))
		if strings.Contains(n, "file_create") || strings.Contains(n, "rename_new_name") {
			hasCreate = true
		}
		if strings.Contains(n, "file_delete") || n == "delete" || strings.Contains(n, "rename_old_name") {
			hasDelete = true
		}
	}
	// ReplaceFile / recreate sets both create and delete on the same name; the file remains.
	if hasCreate {
		return "added"
	}
	if hasDelete {
		return "removed"
	}
	return "modified"
}

func mergeReasonLists(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range append(append([]string{}, a...), b...) {
		k := strings.ToLower(r)
		if r == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, r)
	}
	return out
}
