package evidence

import (
	"bufio"
	"fmt"
	"strings"
)

func parseRegExportFile(content, sid string) ([]RegistryEntry, error) {
	var entries []RegistryEntry
	scanner := bufio.NewScanner(strings.NewReader(content))
	var currentKey string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "Windows Registry Editor") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentKey = mapRegKey(strings.Trim(line, "[]"), sid)
			continue
		}
		if currentKey == "" {
			continue
		}
		name, typ, val, err := parseRegExportLine(line)
		if err != nil {
			continue
		}
		entries = append(entries, RegistryEntry{K: currentKey, N: name, T: typ, V: val})
	}
	return entries, scanner.Err()
}

func parseRegExportLine(line string) (name, typ, val string, err error) {
	eq := strings.Index(line, "=")
	if eq < 0 {
		return "", "", "", fmt.Errorf("invalid line")
	}
	name = strings.Trim(strings.TrimSpace(line[:eq]), `"@`)
	rest := strings.TrimSpace(line[eq+1:])
	if strings.HasPrefix(rest, "dword:") || strings.HasPrefix(rest, "hex") {
		parts := strings.SplitN(rest, ":", 2)
		if len(parts) == 2 {
			return name, parts[0], parts[1], nil
		}
	}
	if strings.HasPrefix(rest, `"`) && strings.HasSuffix(rest, `"`) {
		return name, "REG_SZ", strings.Trim(rest, `"`), nil
	}
	return name, "REG_SZ", rest, nil
}
