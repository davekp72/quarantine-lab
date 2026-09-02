//go:build windows

package diff

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// EnrichNetwork fills DNS/proxy evidence using the existing PowerShell collector.
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
		}
		return
	}
	sysmonFile, err := os.CreateTemp("", "quarantine-sysmon-*.json")
	if err != nil {
		return
	}
	sysmonPath := sysmonFile.Name()
	defer os.Remove(sysmonPath)
	if err := json.NewEncoder(sysmonFile).Encode(addedSysmon); err != nil {
		sysmonFile.Close()
		return
	}
	sysmonFile.Close()

	psScript := fmt.Sprintf(`
$ErrorActionPreference = 'Continue'
. '%s'
$from = ConvertTo-QuarantineNetworkInstant '%s'
$to = ConvertTo-QuarantineNetworkInstant '%s'
if (-not $from -or -not $to) { Write-Error 'invalid capture window'; exit 2 }
$ev = Get-QuarantineNetworkEvidence -ConfigPath '%s' -From $from -To $to
$dns = @($ev.dns)
$sysmon = @()
if (Test-Path -LiteralPath '%s') {
  $raw = Get-Content -Raw -LiteralPath '%s'
  if (-not [string]::IsNullOrWhiteSpace($raw) -and $raw.Trim() -ne '[]' -and $raw.Trim() -ne 'null') {
    $parsed = @($raw | ConvertFrom-Json)
    if ($parsed.Count -gt 0) {
      $sysmon = $parsed
      $dns = Merge-QuarantineSysmonDnsEvidence -DnsEntries @($ev.dns) -SysmonEvents @($sysmon) -From $from -To $to
    }
  }
}
[pscustomobject]@{
  available = [bool]$ev.available -or (@($dns).Count -gt 0) -or (@($ev.requests).Count -gt 0)
  message = [string]$ev.message
  windowFrom = [string]$ev.windowFrom
  windowTo = [string]$ev.windowTo
  sources = $ev.sources
  dns = @($dns)
  requests = @($ev.requests)
  truncated = [bool]$ev.truncated
} | ConvertTo-Json -Depth 12 -Compress
`, escapePSPath(scriptPath),
		escapePSPath(fromCaptured),
		escapePSPath(toCaptured),
		escapePSPath(cfgPath),
		escapePSPath(sysmonPath),
		escapePSPath(sysmonPath))

	out, err := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psScript).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		result.Network = &NetworkSection{
			Available: false,
			Message:   fmt.Sprintf("Network evidence failed: %v (%s)", err, text),
			Sources:   map[string]any{"proxyLogs": []any{}, "pcaps": []any{}},
			DNS:       []map[string]any{},
			Requests:  []map[string]any{},
		}
		return
	}
	var section NetworkSection
	if err := json.Unmarshal([]byte(text), &section); err != nil {
		result.Network = &NetworkSection{
			Available: false,
			Message:   fmt.Sprintf("Network JSON parse failed: %v (%s)", err, truncate(text, 200)),
			Sources:   map[string]any{"proxyLogs": []any{}, "pcaps": []any{}},
		}
		return
	}
	result.Network = &section
	result.Summary.DNSQueries = len(section.DNS)
	result.Summary.NetworkRequests = len(section.Requests)
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
