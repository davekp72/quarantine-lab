package collectors

// SysmonFileChangeKind maps Sysmon file events to added|removed|modified.
// Returns ("", false) for non-file events.
func SysmonFileChangeKind(eid int, typ string) (kind string, ok bool) {
	switch typ {
	case "FileCreate":
		return "added", true
	case "FileCreateStream", "FileCreateStreamHash":
		return "added", true
	case "FileDelete", "FileDeleteDetected":
		return "removed", true
	case "FileCreateTime":
		return "modified", true
	}
	switch eid {
	case 11, 15:
		return "added", true
	case 23, 26:
		return "removed", true
	case 2:
		return "modified", true
	default:
		return "", false
	}
}

// MergeFileChangeKind merges a later classification onto an earlier one for the same path.
func MergeFileChangeKind(pathKinds map[string]string, path, kind string) {
	mergeFileChangeKind(pathKinds, path, kind)
}

func mergeFileChangeKind(pathKinds map[string]string, path, kind string) {
	path = normalizePath(path)
	if path == "" || kind == "" {
		return
	}
	existing, has := pathKinds[path]
	if !has {
		pathKinds[path] = kind
		return
	}
	pathKinds[path] = netUSNKind(existing, kind)
}

// netUSNKind applies a later journal/sysmon classification. A later create wins over
// delete (ReplaceFile / recreate). Modified does not demote a session create.
func netUSNKind(prev, incoming string) string {
	if incoming == "" {
		return prev
	}
	switch incoming {
	case "removed":
		return "removed"
	case "added":
		if prev == "modified" {
			return "modified"
		}
		return "added"
	case "modified":
		if prev == "added" {
			return "added"
		}
		return "modified"
	default:
		if prev != "" {
			return prev
		}
		return incoming
	}
}

// reconcileKindWithDisk corrects USN replace/recreate labeled as removed when the
// file is still on disk at capture time.
func reconcileKindWithDisk(kind string, exists bool) string {
	if exists && kind == "removed" {
		return "added"
	}
	if !exists && kind == "added" {
		return "removed"
	}
	return kind
}
