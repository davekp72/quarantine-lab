//go:build windows

package collectors

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func sysmonEventsPowerShell(logName, baselineAt string, maxEvents int) ([]map[string]any, error) {
	if maxEvents <= 0 {
		maxEvents = 50000
	}
	since := baselineAt
	if since == "" {
		since = time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	}
	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$since = [datetimeoffset]::Parse('%s').UtcDateTime
$ids = 1,2,11,12,13,15,22,23,26
$filter = @{ LogName = '%s'; Id = $ids; StartTime = $since }
$records = Get-WinEvent -FilterHashtable $filter -MaxEvents %d -ErrorAction Stop
$out = foreach ($r in $records) {
  $xml = [xml]$r.ToXml()
  $data = @{}
  foreach ($node in $xml.Event.EventData.Data) { if ($node.Name) { $data[$node.Name] = [string]$node.'#text' } }
  [ordered]@{
    eid = [int]$r.Id
    t = switch ([int]$r.Id) { 1 {'ProcessCreate'} 2 {'FileCreateTime'} 11 {'FileCreate'} 12 {'RegistryEvent'} 13 {'RegistryEvent'} 15 {'FileCreateStreamHash'} 22 {'DnsQuery'} 23 {'FileDelete'} 26 {'FileDeleteDetected'} default {"Event$($r.Id)"} }
    time = $r.TimeCreated.ToUniversalTime().ToString('o')
    target = $data['TargetFilename']
    targetFilename = $data['TargetFilename']
    image = $data['Image']
    commandLine = $data['CommandLine']
    queryName = $data['QueryName']
    targetObject = $data['TargetObject']
    details = $data['Details']
  }
}
$out | ConvertTo-Json -Depth 5 -Compress
`, escapePSSingle(since), escapePSSingle(logName), maxEvents)

	out, err := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("powershell sysmon: %w: %s", err, strings.TrimSpace(string(out)))
	}
	text := strings.TrimSpace(string(out))
	if text == "" || text == "null" {
		return nil, nil
	}
	var events []map[string]any
	if text[0] == '[' {
		if err := json.Unmarshal([]byte(text), &events); err != nil {
			return nil, err
		}
		return events, nil
	}
	var one map[string]any
	if err := json.Unmarshal([]byte(text), &one); err != nil {
		return nil, err
	}
	return []map[string]any{one}, nil
}

func escapePSSingle(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
