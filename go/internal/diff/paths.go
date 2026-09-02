package diff

import (
	"path/filepath"
	"strings"
)

// IsUnresolvedUSNLeafPath reports drive-root leaf paths (C:\name) produced when
// USN journal entries lack a full directory path.
func IsUnresolvedUSNLeafPath(p string) bool {
	p = filepath.Clean(p)
	lower := strings.ToLower(p)
	if strings.Contains(lower, `\_usn_leaf\`) || strings.HasPrefix(lower, `c:\_usn_leaf\`) {
		return true
	}
	if len(p) < 4 || p[1] != ':' {
		return false
	}
	rest := strings.TrimPrefix(p, p[:3])
	return rest != "" && !strings.Contains(rest, `\`)
}

// ShouldHideUSNLeafFile hides unresolved USN leaf paths that have no manifest hash/size.
func ShouldHideUSNLeafFile(f FileDetail) bool {
	if !IsUnresolvedUSNLeafPath(f.Path) {
		return false
	}
	return f.Hash == "" && f.Size == 0
}

func filterUSNLeafFiles(added []FileDetail, removed []FileDetail, modified []FileModified) ([]FileDetail, []FileDetail, []FileModified) {
	filterAdded := make([]FileDetail, 0, len(added))
	for _, f := range added {
		if !ShouldHideUSNLeafFile(f) {
			filterAdded = append(filterAdded, f)
		}
	}
	filterRemoved := make([]FileDetail, 0, len(removed))
	for _, f := range removed {
		if !ShouldHideUSNLeafFile(f) {
			filterRemoved = append(filterRemoved, f)
		}
	}
	filterModified := make([]FileModified, 0, len(modified))
	for _, f := range modified {
		if ShouldHideUSNLeafFile(f.After) || ShouldHideUSNLeafFile(f.Before) {
			continue
		}
		filterModified = append(filterModified, f)
	}
	return filterAdded, filterRemoved, filterModified
}
