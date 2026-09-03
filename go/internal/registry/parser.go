package registry

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"

	"github.com/quarantine-lab/quarantine/internal/evidence"
)

// ParseRegExport parses Windows reg.exe export format into registry entries.
func ParseRegExport(content string) ([]evidence.RegistryEntry, error) {
	var entries []evidence.RegistryEntry
	scanner := bufio.NewScanner(strings.NewReader(content))
	var currentKey string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "Windows Registry Editor") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentKey = strings.Trim(line, "[]")
			continue
		}
		if currentKey == "" {
			continue
		}
		name, typ, val, err := parseRegLine(line)
		if err != nil {
			continue
		}
		entries = append(entries, evidence.RegistryEntry{K: currentKey, N: name, T: typ, V: val})
	}
	return entries, scanner.Err()
}

func parseRegLine(line string) (name, typ, val string, err error) {
	eq := strings.Index(line, "=")
	if eq < 0 {
		return "", "", "", fmt.Errorf("invalid line")
	}
	name = strings.TrimSpace(line[:eq])
	rest := strings.TrimSpace(line[eq+1:])
	if strings.HasPrefix(rest, "hex(") || strings.HasPrefix(rest, "dword:") || strings.HasPrefix(rest, "qword:") {
		parts := strings.SplitN(rest, ":", 2)
		if len(parts) == 2 {
			return unquoteName(name), parts[0], parts[1], nil
		}
	}
	if strings.HasPrefix(rest, `"`) {
		return unquoteName(name), "REG_SZ", strings.Trim(rest, `"`), nil
	}
	return unquoteName(name), "REG_SZ", rest, nil
}

func unquoteName(name string) string {
	return strings.Trim(name, `"@`)
}

// ValueNode is a registry value under a key, with optional change metadata.
type ValueNode struct {
	N      string `json:"n"`
	T      string `json:"t,omitempty"`
	V      any    `json:"v,omitempty"`
	Change string `json:"change,omitempty"`
	Before any    `json:"before,omitempty"`
	After  any    `json:"after,omitempty"`
	BeforeType string `json:"beforeType,omitempty"`
	AfterType  string `json:"afterType,omitempty"`
}

// TreeNode is a nested registry path node for the UI.
type TreeNode struct {
	Name     string               `json:"name"`
	Label    string               `json:"label,omitempty"`
	Path     string               `json:"path"`
	Change   string               `json:"change,omitempty"`
	Values   []ValueNode          `json:"values,omitempty"`
	Children map[string]*TreeNode `json:"children,omitempty"`
}

var sidPartRe = regexp.MustCompile(`(?i)^S-1(?:-\d+)+$`)

// WellKnownSIDs maps common Windows SIDs to friendly names.
var WellKnownSIDs = map[string]string{
	"S-1-5-18":     "SYSTEM",
	"S-1-5-19":     "LOCAL SERVICE",
	"S-1-5-20":     "NETWORK SERVICE",
	"S-1-5-32-544": "Administrators",
	"S-1-5-32-545": "Users",
}

// FriendlySIDLabel returns a display name for a SID path segment.
func FriendlySIDLabel(sid string, sidNames map[string]string) string {
	sid = strings.TrimSpace(sid)
	if sid == "" {
		return sid
	}
	if name, ok := sidNames[sid]; ok && name != "" {
		return name
	}
	for known, label := range WellKnownSIDs {
		if strings.EqualFold(known, sid) {
			return label
		}
	}
	return sid
}

// ChangedEntry is a registry value used when building a change-aware tree.
type ChangedEntry struct {
	Key        string
	Name       string
	Type       string
	Value      any
	Change     string // added | removed | modified
	Before     any
	After      any
	BeforeType string
	AfterType  string
}

// BuildTree indexes registry entries into a path tree (no change coloring).
func BuildTree(entries []evidence.RegistryEntry, sidNames map[string]string) *TreeNode {
	changed := make([]ChangedEntry, 0, len(entries))
	for _, e := range entries {
		changed = append(changed, ChangedEntry{
			Key: e.K, Name: e.N, Type: e.T, Value: e.V,
		})
	}
	return BuildChangedTree(changed, sidNames)
}

// BuildChangedTree builds a registry tree with per-value and per-key change markers.
func BuildChangedTree(entries []ChangedEntry, sidNames map[string]string) *TreeNode {
	if sidNames == nil {
		sidNames = map[string]string{}
	}
	root := &TreeNode{Name: "", Path: "", Children: map[string]*TreeNode{}}
	for _, e := range entries {
		parts := strings.Split(strings.Trim(e.Key, `\`), `\`)
		node := root
		path := ""
		for i, part := range parts {
			if part == "" {
				continue
			}
			if path == "" {
				path = part
			} else {
				path = path + `\` + part
			}
			if node.Children == nil {
				node.Children = map[string]*TreeNode{}
			}
			child, ok := node.Children[part]
			if !ok {
				label := part
				if sidPartRe.MatchString(part) {
					label = FriendlySIDLabel(part, sidNames)
				} else if strings.EqualFold(part, ".DEFAULT") {
					label = ".DEFAULT (system template)"
				}
				child = &TreeNode{Name: part, Label: label, Path: path, Children: map[string]*TreeNode{}}
				node.Children[part] = child
			}
			mergeNodeChange(child, e.Change)
			node = child
			if i == len(parts)-1 {
				vn := ValueNode{
					N: e.Name, T: e.Type, V: e.Value, Change: e.Change,
					Before: e.Before, After: e.After,
					BeforeType: e.BeforeType, AfterType: e.AfterType,
				}
				if e.Change == "modified" {
					if vn.V == nil {
						vn.V = e.After
					}
					if vn.T == "" {
						vn.T = e.AfterType
					}
				}
				node.Values = append(node.Values, vn)
			}
		}
	}
	return root
}

func mergeNodeChange(node *TreeNode, change string) {
	if change == "" {
		return
	}
	if node.Change == "" {
		node.Change = change
		return
	}
	if node.Change == change {
		return
	}
	// Mixed child changes under this key → show as modified.
	node.Change = "modified"
}

// CollectSIDsFromEntries returns unique SID path segments under HKU.
func CollectSIDsFromEntries(entries []evidence.RegistryEntry) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		for _, part := range strings.Split(e.K, `\`) {
			if sidPartRe.MatchString(part) && !seen[part] {
				seen[part] = true
				out = append(out, part)
			}
		}
	}
	return out
}

// CollectSIDsFromChanged returns unique SID path segments from changed entries.
func CollectSIDsFromChanged(entries []ChangedEntry) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		for _, part := range strings.Split(e.Key, `\`) {
			if sidPartRe.MatchString(part) && !seen[part] {
				seen[part] = true
				out = append(out, part)
			}
		}
	}
	return out
}
