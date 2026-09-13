package diff

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/evidence"
)

const largeWebViewFileBytes int64 = 2 * 1024 * 1024

var (
	highSignalFileExt = regexp.MustCompile(`(?i)\.(exe|dll|sys|ps1|bat|cmd|vbs|js|hta|lnk)$`)
	ebWebViewPath     = regexp.MustCompile(`(?i)\\EBWebView\\`)
	ebWebViewNoise    = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\\EBWebView\\Default\\[^\\]+\.tmp$`),
		regexp.MustCompile(`(?i)\\EBWebView\\Default\\Cache\\`),
		regexp.MustCompile(`(?i)\\EBWebView\\Default\\Code Cache\\`),
		regexp.MustCompile(`(?i)\\EBWebView\\Default\\GPUCache\\`),
		regexp.MustCompile(`(?i)\\EBWebView\\Default\\Service Worker\\CacheStorage\\`),
	}
	werNoise = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\\ProgramData\\Microsoft\\Windows\\WER\\`),
		regexp.MustCompile(`(?i)\\Microsoft\\Windows\\WER\\`),
	}
	ephemeralTemp = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\\(?:SystemTemp|Temp)\\__?PSScriptPolicyTest_[^\\]+\.ps1$`),
	}
	compilerTemp = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\.0\.cs$`),
		regexp.MustCompile(`(?i)\.cmdline$`),
		regexp.MustCompile(`(?i)\\Windows\\SystemTemp\\[a-z0-9]{8}(?:\\[a-z0-9]{8}\.(?:dll|err|out))?$`),
		regexp.MustCompile(`(?i)^[a-z0-9]{8}\.(?:dll|err|out|0\.cs|cmdline)$`),
		regexp.MustCompile(`(?i)psscriptpolicytest`),
	}
	usnLeafDir = regexp.MustCompile(`(?i)\\_usn_leaf\\`)
	driveRoot  = regexp.MustCompile(`(?i)^[A-Za-z]:\\[^\\]+$`)
)

func networkHostSuffixesOrDefault(suffixes []string) []string {
	if suffixes == nil {
		return config.DefaultNoiseDomains
	}
	return suffixes
}

func normalizeNoisePath(p string) string {
	return strings.ReplaceAll(p, `/`, `\`)
}

func anyNoiseRE(p string, set []*regexp.Regexp) bool {
	for _, re := range set {
		if re.MatchString(p) {
			return true
		}
	}
	return false
}

func fileSizeHint(f FileDetail, extra ...int64) int64 {
	if f.Size > 0 {
		return f.Size
	}
	for _, n := range extra {
		if n > 0 {
			return n
		}
	}
	return 0
}

func fileNoisePatternsOrDefault(patterns []string) []string {
	if patterns == nil {
		return config.DefaultNoiseFiles
	}
	return patterns
}

func matchFileNoiseSubstring(norm string, patterns []string) bool {
	n := strings.ToLower(norm)
	for _, p := range fileNoisePatternsOrDefault(patterns) {
		p = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), `/`, `\`))
		if p != "" && strings.Contains(n, p) {
			return true
		}
	}
	return false
}

// IsFileNoise matches the Wails noise.js file heuristics using default file patterns.
func IsFileNoise(f FileDetail) bool {
	return IsFileNoisePatterns(f, nil)
}

// IsFileNoisePatterns uses an optional path-substring list (nil = defaults).
func IsFileNoisePatterns(f FileDetail, patterns []string) bool {
	if strings.TrimSpace(f.Noise) != "" {
		return true
	}
	path := strings.TrimSpace(f.Path)
	if path == "" {
		return false
	}
	norm := normalizeNoisePath(path)
	if anyNoiseRE(norm, ephemeralTemp) || anyNoiseRE(norm, compilerTemp) {
		return true
	}
	if highSignalFileExt.MatchString(norm) {
		return false
	}
	if anyNoiseRE(norm, werNoise) {
		return true
	}
	if ebWebViewPath.MatchString(norm) && anyNoiseRE(norm, ebWebViewNoise) {
		if fileSizeHint(f) < largeWebViewFileBytes {
			return true
		}
		return false
	}
	return matchFileNoiseSubstring(norm, patterns)
}

func isModifiedNoise(m FileModified, patterns []string) bool {
	if IsFileNoisePatterns(FileDetail{Path: m.Path, Size: m.After.Size, Noise: m.After.Noise}, patterns) {
		return true
	}
	if m.After.Path != "" && IsFileNoisePatterns(m.After, patterns) {
		return true
	}
	if m.Before.Path != "" && IsFileNoisePatterns(m.Before, patterns) {
		return true
	}
	return false
}

func extractNetworkHost(text string) string {
	raw := strings.ToLower(strings.TrimSpace(text))
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	host := raw
	if i := strings.IndexAny(host, "/?"); i >= 0 {
		host = host[:i]
	}
	if i := strings.Index(host, ":"); i >= 0 {
		host = host[:i]
	}
	return host
}

// IsNetworkHostNoise reports Microsoft/lab telemetry hosts using the default domain list.
func IsNetworkHostNoise(text string) bool {
	return IsNetworkHostNoiseDomains(text, nil)
}

// IsNetworkHostNoiseDomains matches host suffixes. A nil list uses the built-in defaults;
// a non-nil empty list matches only lab hosts (localhost, .local, home.arpa).
func IsNetworkHostNoiseDomains(text string, suffixes []string) bool {
	host := extractNetworkHost(text)
	if host == "" {
		return false
	}
	if host == "home.arpa" || strings.HasSuffix(host, ".home.arpa") {
		return true
	}
	if host == "localhost" || host == "localhost." || strings.HasSuffix(host, ".local") {
		return true
	}
	for _, suffix := range networkHostSuffixesOrDefault(suffixes) {
		suffix = strings.ToLower(strings.TrimSpace(suffix))
		if suffix == "" {
			continue
		}
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func mapString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func isNetworkDNSNoise(m map[string]any, suffixes []string) bool {
	if m == nil {
		return false
	}
	return IsNetworkHostNoiseDomains(mapString(m, "query", "qname", "host"), suffixes)
}

func isNetworkRequestNoise(m map[string]any, suffixes []string) bool {
	if m == nil {
		return false
	}
	return IsNetworkHostNoiseDomains(mapString(m, "host", "url", "path"), suffixes)
}

func isSysmonNoise(m map[string]any, suffixes, files []string) bool {
	if m == nil {
		return false
	}
	for _, key := range []string{"summary", "target", "targetObject", "image", "queryName", "type", "commandLine"} {
		v := mapString(m, key)
		if v == "" {
			continue
		}
		if IsNetworkHostNoiseDomains(v, suffixes) || matchFileNoiseSubstring(normalizeNoisePath(v), files) {
			return true
		}
	}
	return false
}

func isUSNNoise(m map[string]any, files []string) bool {
	return IsFileNoisePatterns(FileDetail{Path: mapString(m, "fileName", "path", "p")}, files)
}

func isUSNLeafFile(f FileDetail) bool {
	p := normalizeNoisePath(f.Path)
	if p == "" {
		return false
	}
	if usnLeafDir.MatchString(p) {
		return true
	}
	if !strings.Contains(p, `\`) && !(len(p) >= 2 && p[1] == ':') {
		return true
	}
	if !driveRoot.MatchString(p) {
		return false
	}
	return f.Hash == "" && f.Size == 0
}

func isUSNLeafModified(m FileModified) bool {
	p := m.Path
	if p == "" {
		p = m.After.Path
	}
	return isUSNLeafFile(FileDetail{Path: p, Hash: m.After.Hash, Size: m.After.Size}) ||
		isUSNLeafFile(m.Before) || isUSNLeafFile(m.After)
}

func cloneResult(in *Result) *Result {
	if in == nil {
		return nil
	}
	out := *in
	out.Meta.Warnings = append([]string(nil), in.Meta.Warnings...)
	out.Files.Added = append([]FileDetail(nil), in.Files.Added...)
	out.Files.Removed = append([]FileDetail(nil), in.Files.Removed...)
	out.Files.Modified = append([]FileModified(nil), in.Files.Modified...)
	out.Sysmon.Added = append([]map[string]any(nil), in.Sysmon.Added...)
	if in.USN != nil {
		u := *in.USN
		u.Events = append([]map[string]any(nil), in.USN.Events...)
		out.USN = &u
	}
	if in.Network != nil {
		n := *in.Network
		n.DNS = append([]map[string]any(nil), in.Network.DNS...)
		n.Requests = cloneMaps(in.Network.Requests)
		if in.Network.Sources != nil {
			n.Sources = mapsClone(in.Network.Sources)
		}
		out.Network = &n
	}
	return &out
}

func cloneMaps(in []map[string]any) []map[string]any {
	if in == nil {
		return nil
	}
	out := make([]map[string]any, len(in))
	for i, m := range in {
		out[i] = mapsClone(m)
	}
	return out
}

func mapsClone(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func stripUSNLeafFiles(in *Result) *Result {
	if in == nil {
		return nil
	}
	added := in.Files.Added[:0:0]
	for _, f := range in.Files.Added {
		if !isUSNLeafFile(f) {
			added = append(added, f)
		}
	}
	removed := in.Files.Removed[:0:0]
	for _, f := range in.Files.Removed {
		if !isUSNLeafFile(f) {
			removed = append(removed, f)
		}
	}
	modified := in.Files.Modified[:0:0]
	for _, f := range in.Files.Modified {
		if !isUSNLeafModified(f) {
			modified = append(modified, f)
		}
	}
	in.Files.Added = added
	in.Files.Removed = removed
	in.Files.Modified = modified
	in.Summary.FilesAdded = len(added)
	in.Summary.FilesRemoved = len(removed)
	in.Summary.FilesModified = len(modified)
	return in
}

func recountSummary(in *Result) {
	if in == nil {
		return
	}
	in.Summary.FilesAdded = len(in.Files.Added)
	in.Summary.FilesRemoved = len(in.Files.Removed)
	in.Summary.FilesModified = len(in.Files.Modified)
	in.Summary.SysmonAdded = len(in.Sysmon.Added)
	if in.Network != nil {
		in.Summary.DNSQueries = len(in.Network.DNS)
		in.Summary.NetworkRequests = len(in.Network.Requests)
	}
	in.Summary.RegistryAdded = len(in.Registry.Added)
	in.Summary.RegistryRemoved = len(in.Registry.Removed)
	in.Summary.RegistryModified = len(in.Registry.Modified)
	if in.USN != nil {
		in.USN.EventCount = len(in.USN.Events)
	}
}

func registryNoisePatternsOrDefault(patterns []string) []string {
	if patterns == nil {
		return config.DefaultNoiseRegistry
	}
	return patterns
}

// IsRegistryNoise reports a volatile/cache registry key using an optional substring list.
func IsRegistryNoise(key string, patterns []string) bool {
	n := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(key), `/`, `\`))
	if n == "" {
		return false
	}
	for _, p := range registryNoisePatternsOrDefault(patterns) {
		p = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), `/`, `\`))
		if p != "" && strings.Contains(n, p) {
			return true
		}
	}
	return false
}

// FilterResult copies the diff and drops routine noise using the default lists.
func FilterResult(in *Result, hideNoise bool) *Result {
	return FilterResultWith(in, hideNoise, nil, nil, nil)
}

// FilterResultWith is FilterResult with optional domain, file, and registry lists (nil = defaults).
func FilterResultWith(in *Result, hideNoise bool, domains, files, registry []string) *Result {
	out := cloneResult(in)
	out = stripUSNLeafFiles(out)
	if out == nil || !hideNoise {
		if out != nil {
			recountSummary(out)
		}
		return out
	}
	added := make([]FileDetail, 0, len(out.Files.Added))
	for _, f := range out.Files.Added {
		if !IsFileNoisePatterns(f, files) {
			added = append(added, f)
		}
	}
	removed := make([]FileDetail, 0, len(out.Files.Removed))
	for _, f := range out.Files.Removed {
		if !IsFileNoisePatterns(f, files) {
			removed = append(removed, f)
		}
	}
	modified := make([]FileModified, 0, len(out.Files.Modified))
	for _, f := range out.Files.Modified {
		if !isModifiedNoise(f, files) {
			modified = append(modified, f)
		}
	}
	out.Files.Added = added
	out.Files.Removed = removed
	out.Files.Modified = modified

	sys := make([]map[string]any, 0, len(out.Sysmon.Added))
	for _, ev := range out.Sysmon.Added {
		if !isSysmonNoise(ev, domains, files) {
			sys = append(sys, ev)
		}
	}
	out.Sysmon.Added = sys

	if out.USN != nil {
		keep := make([]map[string]any, 0, len(out.USN.Events))
		for _, ev := range out.USN.Events {
			if !isUSNNoise(ev, files) {
				keep = append(keep, ev)
			}
		}
		out.USN.Events = keep
	}
	if out.Network != nil {
		dns := make([]map[string]any, 0, len(out.Network.DNS))
		for _, ev := range out.Network.DNS {
			if !isNetworkDNSNoise(ev, domains) {
				dns = append(dns, ev)
			}
		}
		reqs := make([]map[string]any, 0, len(out.Network.Requests))
		for _, ev := range out.Network.Requests {
			if !isNetworkRequestNoise(ev, domains) {
				reqs = append(reqs, ev)
			}
		}
		out.Network.DNS = dns
		out.Network.Requests = reqs
	}

	regAdded := make([]evidence.RegistryEntry, 0, len(out.Registry.Added))
	for _, e := range out.Registry.Added {
		if !IsRegistryNoise(e.K, registry) {
			regAdded = append(regAdded, e)
		}
	}
	regRemoved := make([]evidence.RegistryEntry, 0, len(out.Registry.Removed))
	for _, e := range out.Registry.Removed {
		if !IsRegistryNoise(e.K, registry) {
			regRemoved = append(regRemoved, e)
		}
	}
	regModified := make([]RegistryModified, 0, len(out.Registry.Modified))
	for _, e := range out.Registry.Modified {
		if !IsRegistryNoise(e.Key, registry) {
			regModified = append(regModified, e)
		}
	}
	dropped := (len(out.Registry.Added) - len(regAdded)) + (len(out.Registry.Removed) - len(regRemoved)) + (len(out.Registry.Modified) - len(regModified))
	out.Registry.Added = regAdded
	out.Registry.Removed = regRemoved
	out.Registry.Modified = regModified
	if dropped > 0 {
		out.Summary.RegistryVolatileFiltered += dropped
	}

	recountSummary(out)
	return out
}
