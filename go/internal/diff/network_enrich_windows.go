//go:build windows

package diff

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// EnrichNetwork fills DNS/proxy evidence from host PCAP/proxy logs, then merges Sysmon DNS in Go.
func EnrichNetwork(cfgPath, projectRoot string, result *Result, fromCaptured, toCaptured string, addedSysmon []map[string]any) {
	if result == nil || fromCaptured == "" || toCaptured == "" {
		return
	}
	cfgPath = absPath(cfgPath)
	projectRoot = absPath(projectRoot)
	scriptPath := filepath.Join(projectRoot, "manifest", "Get-QuarantineNetworkEvidence.ps1")
	if _, err := os.Stat(scriptPath); err != nil {
		result.Network = &NetworkSection{
			Available: false,
			Message:   fmt.Sprintf("Network script not found: %s", scriptPath),
			Sources:   map[string]any{"proxyLogs": []any{}, "pcaps": []any{}},
			DNS:       []map[string]any{},
			Requests:  []map[string]any{},
		}
		mergeSysmonDNS(result, fromCaptured, toCaptured, addedSysmon)
		return
	}

	psScript := fmt.Sprintf(`
$ErrorActionPreference = 'Continue'
. '%s'
$from = ConvertTo-QuarantineNetworkInstant '%s'
$to = ConvertTo-QuarantineNetworkInstant '%s'
if (-not $from -or -not $to) { Write-Error 'invalid capture window'; exit 2 }
$ev = Get-QuarantineNetworkEvidence -ConfigPath '%s' -From $from -To $to
[pscustomobject]@{
  available = [bool]$ev.available
  message = [string]$ev.message
  windowFrom = [string]$ev.windowFrom
  windowTo = [string]$ev.windowTo
  sources = $ev.sources
  dns = @($ev.dns)
  requests = @($ev.requests)
  truncated = [bool]$ev.truncated
} | ConvertTo-Json -Depth 12 -Compress
`, escapePSPath(scriptPath),
		escapePSPath(fromCaptured),
		escapePSPath(toCaptured),
		escapePSPath(cfgPath))

	out, err := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psScript).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		result.Network = &NetworkSection{
			Available: false,
			Message:   fmt.Sprintf("Network evidence failed: %v (%s)", err, truncate(text, 200)),
			Sources:   map[string]any{"proxyLogs": []any{}, "pcaps": []any{}},
			DNS:       []map[string]any{},
			Requests:  []map[string]any{},
		}
		mergeSysmonDNS(result, fromCaptured, toCaptured, addedSysmon)
		return
	}
	var section NetworkSection
	if err := json.Unmarshal([]byte(text), &section); err != nil {
		result.Network = &NetworkSection{
			Available: false,
			Message:   fmt.Sprintf("Network JSON parse failed: %v (%s)", err, truncate(text, 200)),
			Sources:   map[string]any{"proxyLogs": []any{}, "pcaps": []any{}},
			DNS:       []map[string]any{},
			Requests:  []map[string]any{},
		}
		mergeSysmonDNS(result, fromCaptured, toCaptured, addedSysmon)
		return
	}
	if section.DNS == nil {
		section.DNS = []map[string]any{}
	}
	if section.Requests == nil {
		section.Requests = []map[string]any{}
	}
	result.Network = &section
	mergeSysmonDNS(result, fromCaptured, toCaptured, addedSysmon)
	result.Summary.DNSQueries = len(result.Network.DNS)
	result.Summary.NetworkRequests = len(result.Network.Requests)
}

// mergeSysmonDNS appends Event-22 / DnsQuery rows from Sysmon into result.Network.
// Done in Go because PowerShell ConvertFrom-Json often nests large top-level arrays
// (Count=1 wrapping the real events), which previously dropped all Sysmon DNS.
func mergeSysmonDNS(result *Result, fromCaptured, toCaptured string, addedSysmon []map[string]any) {
	if result == nil {
		return
	}
	if result.Network == nil {
		result.Network = &NetworkSection{
			Available: false,
			Sources:   map[string]any{"proxyLogs": []any{}, "pcaps": []any{}},
			DNS:       []map[string]any{},
			Requests:  []map[string]any{},
		}
	}
	fromT, fromOK := parseNetworkInstant(fromCaptured)
	toT, toOK := parseNetworkInstant(toCaptured)

	seen := map[string]bool{}
	for _, d := range result.Network.DNS {
		q, _ := d["query"].(string)
		if q == "" {
			q, _ = d["qname"].(string)
		}
		t, _ := d["t"].(string)
		src, _ := d["source"].(string)
		seen[strings.ToLower(q)+"|"+t+"|"+src] = true
	}

	var added int
	for _, ev := range addedSysmon {
		if !isSysmonDNS(ev) {
			continue
		}
		query := strings.TrimSpace(stringFromMap(ev, "queryName"))
		if query == "" {
			continue
		}
		query = strings.TrimSuffix(query, ".")
		timeText := stringFromMap(ev, "time")
		ts, tsOK := parseNetworkInstant(timeText)
		if tsOK {
			if fromOK && ts.Before(fromT) {
				continue
			}
			if toOK && ts.After(toT) {
				continue
			}
			timeText = ts.UTC().Format(time.RFC3339Nano)
		}
		key := strings.ToLower(query) + "|" + timeText + "|sysmon"
		if seen[key] {
			continue
		}
		seen[key] = true
		result.Network.DNS = append(result.Network.DNS, map[string]any{
			"t":      timeText,
			"query":  query,
			"type":   "",
			"source": "sysmon",
			"image":  stringFromMap(ev, "image"),
		})
		added++
	}

	if added > 0 {
		result.Network.Available = true
		sort.SliceStable(result.Network.DNS, func(i, j int) bool {
			ti, _ := result.Network.DNS[i]["t"].(string)
			tj, _ := result.Network.DNS[j]["t"].(string)
			if ti != tj {
				return ti < tj
			}
			qi, _ := result.Network.DNS[i]["query"].(string)
			qj, _ := result.Network.DNS[j]["query"].(string)
			return qi < qj
		})
		if strings.Contains(strings.ToLower(result.Network.Message), "no dns") ||
			strings.Contains(strings.ToLower(result.Network.Message), "no network") ||
			result.Network.Message == "" {
			result.Network.Message = fmt.Sprintf("Includes %d DNS lookup(s) from Sysmon Event 22.", added)
		} else if !strings.Contains(strings.ToLower(result.Network.Message), "sysmon") {
			result.Network.Message += fmt.Sprintf(" Also %d DNS lookup(s) from Sysmon Event 22.", added)
		}
	}

	result.Summary.DNSQueries = len(result.Network.DNS)
	result.Summary.NetworkRequests = len(result.Network.Requests)
}

func isSysmonDNS(ev map[string]any) bool {
	if eid := intFromMap(ev, "eid"); eid == 22 {
		return true
	}
	kind := strings.TrimSpace(stringFromMap(ev, "t"))
	if kind == "" {
		kind = strings.TrimSpace(stringFromMap(ev, "type"))
	}
	return strings.EqualFold(kind, "DnsQuery")
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

func intFromMap(m map[string]any, key string) int {
	if m == nil {
		return 0
	}
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch t := v.(type) {
	case float64:
		return int(t)
	case float32:
		return int(t)
	case int:
		return t
	case int64:
		return int(t)
	case json.Number:
		n, _ := t.Int64()
		return int(n)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(t))
		return n
	default:
		return 0
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
	if ts, err := time.Parse(time.RFC3339Nano, text); err == nil {
		return ts, true
	}
	return time.Time{}, false
}

func absPath(p string) string {
	if p == "" {
		return p
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}

func escapePSPath(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
