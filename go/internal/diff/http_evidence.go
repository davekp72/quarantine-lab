package diff

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/httpbody"
)

var accessLogLine = regexp.MustCompile(`^(\S+)\s+(\S+)\s+(.+)$`)

// attachSnapshotHTTP replaces Network.Requests with rows parsed from the To
// snapshot's evidence-network package. Avoids PowerShell ConvertTo-Json, which
// emits invalid `\a`/`\v` escapes when mitm bodies contain control bytes.
func attachSnapshotHTTP(cfgPath string, result *Result) {
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
	if t, _ := reqs[0]["t"].(string); t != "" && result.Network.WindowFrom == "" {
		result.Network.WindowFrom = t
	}
	if t, _ := reqs[len(reqs)-1]["t"].(string); t != "" && result.Network.WindowTo == "" {
		result.Network.WindowTo = t
	}
	result.Summary.NetworkRequests = len(reqs)
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
		host := strings.TrimSpace(rec.Host)
		if host == "" {
			host = hostFromURL(rec.URL)
		}
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
		return rest
	}
	return ""
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
