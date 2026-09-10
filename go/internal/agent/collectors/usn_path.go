package collectors

import (
	"path/filepath"
	"strings"
)

func resolveUsnPathFallback(name string) string {
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
	lower := strings.ToLower(name)
	if lower == "hosts" || strings.HasSuffix(lower, `\hosts`) {
		return `C:\Windows\System32\drivers\etc\hosts`
	}
	// Bare USN filenames are not full paths — do not invent C:\name.
	return ""
}

func isUnresolvedFileName(p string) bool {
	p = strings.TrimSpace(p)
	if p == "" {
		return true
	}
	p = strings.ReplaceAll(p, "/", `\`)
	if strings.Contains(p, `\`) {
		return false
	}
	return len(p) < 2 || p[1] != ':'
}

func isLeafOnlyPath(p string) bool {
	p = normalizePath(p)
	if isUnresolvedFileName(p) {
		return true
	}
	if len(p) < 4 || p[1] != ':' {
		return false
	}
	rest := strings.TrimPrefix(p, p[:3])
	rest = strings.TrimPrefix(rest, `\`)
	return rest != "" && !strings.Contains(rest, `\`)
}
