package collectors

import (
	"strconv"
	"strings"
)

func parseUsnValue(v string) (uint64, error) {
	v = strings.TrimSpace(strings.Trim(v, `"`))
	if v == "" {
		return 0, strconv.ErrSyntax
	}
	if strings.HasPrefix(strings.ToLower(v), "ref:") {
		return 0, nil
	}
	if strings.HasPrefix(strings.ToLower(v), "0x") {
		return strconv.ParseUint(v[2:], 16, 64)
	}
	return strconv.ParseUint(v, 10, 64)
}

func usnFromEvent(ev map[string]any) uint64 {
	s, _ := ev["usn"].(string)
	n, err := parseUsnValue(s)
	if err != nil {
		return 0
	}
	return n
}

func reasonStringsFromEvent(ev map[string]any) []string {
	raw, ok := ev["reason"]
	if !ok {
		raw = ev["reasons"]
	}
	switch v := raw.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func reasonCodeFromEvent(ev map[string]any) string {
	s, _ := ev["reasonCode"].(string)
	return s
}
