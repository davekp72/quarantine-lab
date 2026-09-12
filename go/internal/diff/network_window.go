package diff

import (
	"fmt"
	"strings"
	"time"
)

func looksLikeIP(s string) bool {
	if s == "" {
		return false
	}
	// IPv4
	if strings.Count(s, ".") == 3 {
		ok := true
		for _, p := range strings.Split(s, ".") {
			if p == "" {
				ok = false
				break
			}
			for _, c := range p {
				if c < '0' || c > '9' {
					ok = false
					break
				}
			}
		}
		if ok {
			return true
		}
	}
	// IPv6 (very loose)
	return strings.Contains(s, ":") && !strings.ContainsAny(s, " /")
}

func stringFromMap(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

func parseNetworkInstant(text string) (time.Time, bool) {
	text = strings.TrimSpace(text)
	if text == "" {
		return time.Time{}, false
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.9999999Z07:00",
		"2006-01-02T15:04:05.9999999Z",
		"2006-01-02T15:04:05Z07:00",
	}
	for _, layout := range layouts {
		if ts, err := time.Parse(layout, text); err == nil {
			return ts, true
		}
	}
	return time.Time{}, false
}
