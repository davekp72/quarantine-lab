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

// MergeFileChangeKind merges a path/kind into a path→kind map (removed > modified > added).
func MergeFileChangeKind(pathKinds map[string]string, path, kind string) {
	mergeFileChangeKind(pathKinds, path, kind)
}

func mergeFileChangeKind(pathKinds map[string]string, path, kind string) {
	path = normalizePath(path)
	if path == "" {
		return
	}
	existing, has := pathKinds[path]
	if !has {
		pathKinds[path] = kind
		return
	}
	if kind == "removed" {
		pathKinds[path] = "removed"
		return
	}
	if kind == "modified" {
		if existing != "removed" {
			pathKinds[path] = "modified"
		}
		return
	}
	// added
	if existing == "modified" || existing == "removed" {
		return
	}
	pathKinds[path] = "added"
}
