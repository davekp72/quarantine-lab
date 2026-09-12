package diff

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/httpbody"
)

var accessLogLine = regexp.MustCompile(`^(\S+)\s+(\S+)\s+(.+)$`)

const networkClockSkew = 30 * time.Minute

// attachSnapshotHTTP replaces Network.Requests with rows parsed from the To
// snapshot's evidence-network package. Avoids PowerShell ConvertTo-Json, which
// emits invalid `\a`/`\v` escapes when mitm bodies contain control bytes.
// Rows are clipped to the CleanSession→Evidence window (with skew / duration fallback).
func attachSnapshotHTTP(cfgPath string, result *Result, fromCaptured, toCaptured string) {
	if result == nil {
		return
	}
	snap := strings.TrimSpace(result.Meta.ToSnapshot)
	if snap == "" {
		return
	}
	logDir := manifestLogDirFromConfig(cfgPath)
	if logDir == "" {
		return
	}
	dir := filepath.Join(logDir, config.SafeSnapshotFileName(snap)+"-network")
	reqs, sources := ReadNetworkHTTP(dir)
	reqs = FilterHTTPBySnapshotWindow(reqs, fromCaptured, toCaptured)
	if len(reqs) == 0 {
		return
	}
	if result.Network == nil {
		result.Network = &NetworkSection{
			Sources:  map[string]any{"proxyLogs": []any{}, "pcaps": []any{}},
			DNS:      []map[string]any{},
			Requests: []map[string]any{},
		}
	}
	result.Network.Requests = reqs
	result.Network.Available = true
	if result.Network.Sources == nil {
		result.Network.Sources = map[string]any{}
	}
	result.Network.Sources["proxyLogs"] = sources
	if strings.Contains(strings.ToLower(result.Network.Message), "json parse failed") ||
		strings.Contains(strings.ToLower(result.Network.Message), "network evidence failed") ||
		result.Network.Message == "" {
		result.Network.Message = "Decrypted HTTPS from mitmproxy flows.jsonl (click a request for bodies)."
	}
	if t, _ := reqs[0]["t"].(string); t != "" {
		result.Network.WindowFrom = t
	}
	if t, _ := reqs[len(reqs)-1]["t"].(string); t != "" {
		result.Network.WindowTo = t
	}
	result.Summary.NetworkRequests = len(reqs)
}

// FilterHTTPBySnapshotWindow keeps HTTP rows for the guest snapshot interval.
// Prefer absolute From/To with clock skew; if that window is empty (guest vs
// gateway clock far apart) or spans far longer than the snapshot gap (skew
// pulled in leftover package traffic), keep only the tail matching the gap.
func FilterHTTPBySnapshotWindow(reqs []map[string]any, fromCaptured, toCaptured string) []map[string]any {
	if len(reqs) == 0 {
		return reqs
	}
	fromT, fromOK := parseNetworkInstant(fromCaptured)
	toT, toOK := parseNetworkInstant(toCaptured)
	if !fromOK || !toOK {
		return reqs
	}
	if toT.Before(fromT) {
		fromT, toT = toT, fromT
	}
	session := toT.Sub(fromT)
	if session < 2*time.Minute {
		session = 2 * time.Minute
	}

	looseFrom := fromT.Add(-networkClockSkew)
	looseTo := toT.Add(networkClockSkew)
	var abs []map[string]any
	var parsed []struct {
		row map[string]any
		t   time.Time
	}
	var maxT time.Time
	for _, r := range reqs {
		t, ok := parseNetworkInstant(stringFromMap(r, "t"))
		if !ok {
			continue
		}
		parsed = append(parsed, struct {
			row map[string]any
			t   time.Time
		}{r, t})
		if maxT.IsZero() || t.After(maxT) {
			maxT = t
		}
		if !t.Before(looseFrom) && !t.After(looseTo) {
			abs = append(abs, r)
		}
	}
	if len(parsed) == 0 {
		return reqs
	}
	if len(abs) > 0 {
		absSpan := httpTimeSpan(abs)
		// Skew can admit ~hour of pre-session junk; clip to session-sized tail.
		if absSpan <= session+2*networkClockSkew && absSpan <= session+10*time.Minute {
			return abs
		}
	}
	pad := 2 * time.Minute
	if session/4 > pad {
		pad = session / 4
	}
	cut := maxT.Add(-(session + pad))
	out := make([]map[string]any, 0, len(parsed))
	for _, p := range parsed {
		if !p.t.Before(cut) {
			out = append(out, p.row)
		}
	}
	if len(out) == 0 {
		return reqs
	}
	return out
}

func httpTimeSpan(reqs []map[string]any) time.Duration {
	var minT, maxT time.Time
	for _, r := range reqs {
		t, ok := parseNetworkInstant(stringFromMap(r, "t"))
		if !ok {
			continue
		}
		if minT.IsZero() || t.Before(minT) {
			minT = t
		}
		if maxT.IsZero() || t.After(maxT) {
			maxT = t
		}
	}
	if minT.IsZero() || maxT.IsZero() {
		return 0
	}
	return maxT.Sub(minT)
}

// FilterDNSBySnapshotWindow mirrors FilterHTTPBySnapshotWindow for DNS rows.
func FilterDNSBySnapshotWindow(rows []map[string]any, fromCaptured, toCaptured string) []map[string]any {
	return FilterHTTPBySnapshotWindow(rows, fromCaptured, toCaptured)
}

// DedupDNSByQuery keeps one row per query name (prefer sysmon > pcap > mitm/proxy)
// and drops IP-literal "queries" inferred from HTTP hosts.
func DedupDNSByQuery(rows []map[string]any) []map[string]any {
	if len(rows) == 0 {
		return rows
	}
	priority := func(src string) int {
		switch strings.ToLower(strings.TrimSpace(src)) {
		case "sysmon":
			return 4
		case "pcap":
			return 3
		case "sni":
			return 2
		case "mitm", "proxy":
			return 1
		default:
			return 0
		}
	}
	best := map[string]map[string]any{}
	order := []string{}
	for _, r := range rows {
		q := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(stringFromMap(r, "query")), "."))
		if q == "" {
			q = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(stringFromMap(r, "qname")), "."))
		}
		if q == "" || looksLikeIP(q) {
			continue
		}
		src, _ := r["source"].(string)
		prev, ok := best[q]
		if !ok {
			best[q] = r
			order = append(order, q)
			continue
		}
		prevSrc, _ := prev["source"].(string)
		if priority(src) > priority(prevSrc) {
			best[q] = r
			continue
		}
		// Merge answers onto the preferred row.
		if priority(src) == priority(prevSrc) {
			mergeDNSAnswers(prev, r)
		} else {
			mergeDNSAnswers(best[q], r)
		}
	}
	out := make([]map[string]any, 0, len(order))
	for _, q := range order {
		out = append(out, best[q])
	}
	sort.SliceStable(out, func(i, j int) bool {
		ti, _ := out[i]["t"].(string)
		tj, _ := out[j]["t"].(string)
		if ti != tj {
			return ti < tj
		}
		qi, _ := out[i]["query"].(string)
		qj, _ := out[j]["query"].(string)
		return qi < qj
	})
	return out
}

func mergeDNSAnswers(dst, src map[string]any) {
	if dst == nil || src == nil {
		return
	}
	var existing []string
	switch v := dst["answers"].(type) {
	case []string:
		existing = append([]string{}, v...)
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok && s != "" {
				existing = append(existing, s)
			}
		}
	}
	seen := map[string]bool{}
	for _, s := range existing {
		seen[s] = true
	}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		existing = append(existing, s)
	}
	switch v := src["answers"].(type) {
	case []string:
		for _, s := range v {
			add(s)
		}
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok {
				add(s)
			}
		}
	}
	if len(existing) > 0 {
		dst["answers"] = existing
	}
}

// ReadNetworkHTTP loads HTTP/proxy rows from an evidence-network directory.
// Prefers flows.jsonl (decrypted mitm); falls back to access.log.
func ReadNetworkHTTP(dir string) (requests []map[string]any, sources []string) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, nil
	}
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return nil, nil
	}
	flowsPath := filepath.Join(dir, "flows.jsonl")
	if recs := readFlowsJSONL(flowsPath); len(recs) > 0 {
		return recs, []string{flowsPath}
	}
	accessPath := filepath.Join(dir, "access.log")
	if recs := readProxyAccessLog(accessPath); len(recs) > 0 {
		return recs, []string{accessPath}
	}
	return nil, nil
}

func readFlowsJSONL(path string) []map[string]any {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 8<<20)
	var out []map[string]any
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		var rec httpbody.FlowRecord
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			continue
		}
		if isNetworkNoiseURL(rec.URL) {
			continue
		}
		host := httpDisplayHost(rec.Host, rec.URL)
		out = append(out, map[string]any{
			"t":           rec.T,
			"method":      rec.Method,
			"url":         rec.URL,
			"host":        host,
			"status":      rec.Status,
			"source":      "mitm",
			"hasBody":     true,
			"flowFile":    path,
			"flowLine":    lineNo,
			"resolvedIps": rec.ResolvedIPs,
		})
	}
	sortHTTPRequests(out)
	return out
}

func readProxyAccessLog(path string) []map[string]any {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var out []map[string]any
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		m := accessLogLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		url := strings.TrimSpace(m[3])
		if isNetworkNoiseURL(url) {
			continue
		}
		out = append(out, map[string]any{
			"t":       m[1],
			"method":  m[2],
			"url":     url,
			"host":    hostFromURL(url),
			"source":  "proxy",
			"hasBody": false,
		})
	}
	sortHTTPRequests(out)
	return out
}

func isNetworkNoiseURL(url string) bool {
	lower := strings.ToLower(strings.TrimSpace(url))
	if lower == "" {
		return true
	}
	if strings.Contains(lower, "quarantine.pac") {
		return true
	}
	if strings.Contains(lower, "mitmproxy-ca-cert.cer") {
		return true
	}
	if strings.Contains(lower, "/cert.cer?") || strings.HasSuffix(lower, "/cert.cer") {
		return true
	}
	if strings.HasPrefix(lower, "http://127.0.0.1") || strings.HasPrefix(lower, "https://127.0.0.1") {
		return true
	}
	if strings.HasPrefix(lower, "http://localhost") || strings.HasPrefix(lower, "https://localhost") {
		return true
	}
	return false
}

func hostFromURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "://"); i >= 0 {
		rest := raw[i+3:]
		if j := strings.IndexAny(rest, "/:"); j >= 0 {
			rest = rest[:j]
		}
		// Strip IPv6 brackets if present.
		rest = strings.TrimPrefix(rest, "[")
		rest = strings.TrimSuffix(rest, "]")
		return rest
	}
	return ""
}

// httpDisplayHost prefers the URL hostname over mitm's request.host.
// Transparent MITM often stores the peer IP in host while pretty_url has the domain.
func httpDisplayHost(recHost, url string) string {
	fromURL := hostFromURL(url)
	host := strings.TrimSpace(recHost)
	if fromURL != "" && !looksLikeIP(fromURL) {
		return fromURL
	}
	if host != "" && !looksLikeIP(host) {
		return host
	}
	if fromURL != "" {
		return fromURL
	}
	return host
}

func sortHTTPRequests(rows []map[string]any) {
	sort.SliceStable(rows, func(i, j int) bool {
		ti, _ := rows[i]["t"].(string)
		tj, _ := rows[j]["t"].(string)
		if ti != tj {
			return ti < tj
		}
		ui, _ := rows[i]["url"].(string)
		uj, _ := rows[j]["url"].(string)
		return ui < uj
	})
}

func manifestLogDirFromConfig(cfgPath string) string {
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return ""
	}
	var cfg struct {
		VMDataDir string `json:"vmDataDir"`
		Manifest  struct {
			LogDir string `json:"logDir"`
		} `json:"manifest"`
	}
	if json.Unmarshal(raw, &cfg) != nil {
		return ""
	}
	if strings.TrimSpace(cfg.Manifest.LogDir) != "" {
		return cfg.Manifest.LogDir
	}
	if strings.TrimSpace(cfg.VMDataDir) != "" {
		return filepath.Join(cfg.VMDataDir, "logs", "manifests")
	}
	return ""
}
