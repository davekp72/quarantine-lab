package registry

import (
	"bufio"
	"fmt"
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

// BuildTree builds nested registry tree from flat entries for UI.
type TreeNode struct {
	Name     string                `json:"name"`
	Path     string                `json:"path"`
	Values   []evidence.RegistryEntry `json:"values,omitempty"`
	Children map[string]*TreeNode  `json:"children,omitempty"`
}

// BuildTree indexes registry entries into a path tree.
func BuildTree(entries []evidence.RegistryEntry) *TreeNode {
	root := &TreeNode{Name: "", Path: "", Children: map[string]*TreeNode{}}
	for _, e := range entries {
		parts := strings.Split(strings.Trim(e.K, `\`), `\`)
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
				child = &TreeNode{Name: part, Path: path, Children: map[string]*TreeNode{}}
				node.Children[part] = child
			}
			node = child
			if i == len(parts)-1 {
				node.Values = append(node.Values, e)
			}
		}
	}
	return root
}
