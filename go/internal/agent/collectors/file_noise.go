package collectors

import (
	"path/filepath"
	"strings"
)

// High-value extensions always stay in the file list, even under Temp/cache.
var signalExt = map[string]bool{
	".exe": true, ".dll": true, ".sys": true, ".scr": true, ".cpl": true,
	".ocx": true, ".drv": true, ".efi": true, ".ps1": true, ".bat": true,
	".cmd": true, ".vbs": true, ".js": true, ".jse": true, ".wsf": true,
	".wsh": true, ".msi": true, ".msp": true, ".com": true, ".pif": true,
	".hta": true, ".inf": true, ".reg": true, ".iso": true, ".img": true,
	".vhd": true, ".vhdx": true, ".lnk": true,
}

var noiseNames = map[string]bool{
	"ntuser.dat": true, "ntuser.dat.log1": true, "ntuser.dat.log2": true,
	"usrclass.dat": true, "usrclass.dat.log1": true, "usrclass.dat.log2": true,
	"iconcache.db": true, "thumbs.db": true, "thumbcache_idx.db": true,
	"privileged-job.done": true, "ngen.log": true, "sru.log": true, "srutmp.log": true,
	"cache0.bin": true, "cachev3.dat": true, "desktop.ini": true,
	"inventorydriverbinary.db-journal": true, "inventorydevicepnp.db-journal": true,
}

var noiseNameContains = []string{
	"report.wer", ".wer.tmp", ".db-journal", ".db-wal", ".db-shm",
	".dxcache", "dxcache-shm", "dxcache-wal",
	"hklm-hklm_", "hklm-registry-", "startupprofiledata-",
	"__psscriptpolicytest_", "prep_activatable class_",
}

var noisePathParts = []string{
	`\appdata\local\microsoft\windows\inetcache\`,
	`\appdata\local\microsoft\windows\webcache\`,
	`\appdata\local\microsoft\windows\history\`,
	`\appdata\local\microsoft\windows\temporary internet files\`,
	`\appdata\local\microsoft\windows\caches\`,
	`\appdata\local\microsoft\windows\notifications\`,
	`\appdata\local\microsoft\windows\explorer\thumbcache`,
	`\appdata\local\microsoft\windows\inetcookies\`,
	`\appdata\local\d3dscache\`,
	`\appdata\local\fontconfig\`,
	`\appdata\local\temp\`,
	`\appdata\local\crashdumps\`,
	`\appdata\local\package cache\`,
	`\appdata\roaming\microsoft\windows\recent\`,
	`\windows\prefetch\`,
	`\windows\temp\`,
	`\windows\logs\`,
	`\windows\softwaredistribution\`,
	`\windows\servicestates\`,
	`\windows\serviceprofiles\`,
	`\windows\system32\config\systemprofile\appdata\`,
	`\windows\system32\spp\store\`,
	`\windows\system32\winevt\logs\`,
	`\windows\system32\wbem\repository\`,
	`\windows\system32\config\journal\`,
	`\windows\cbstemp\`,
	`\windows\winsxs\temp\`,
	`\windows\appcompat\`,
	`\programdata\microsoft\windows\wer\`,
	`\programdata\microsoft\diagnosis\`,
	`\programdata\microsoft\search\`,
	`\programdata\microsoft\windows defender\scans\`,
	`\programdata\microsoft\windows defender\support\`,
	`\programdata\microsoft\windows\caches\`,
	`\users\public\quarantine\`,
}

var browserCacheParts = []string{
	`\cache\cache_data\`,
	`\code cache\`,
	`\gpuCache\`,
	`\shadercache\`,
	`\service worker\`,
	`\dawncache\`,
	`\optimizationguide`,
	`\safebrowsing\`,
	`\jump list icons\`,
	`\edge\user data\`,
	`\google\chrome\user data\`,
	`\microsoft\edge\user data\`,
	`\mozilla\firefox\profiles\`,
	`\chromium\user data\`,
}

var captureSelfParts = []string{
	`\users\public\quarantine\`,
	`\hives\`,
}

// ClassifyFileNoise returns "" for analyst-relevant paths, or a noise class to hide
// from the main file list. Signal extensions and System32/etc always keep.
func ClassifyFileNoise(path, fileName string) string {
	p := strings.ToLower(strings.ReplaceAll(filepath.Clean(path), "/", `\`))
	n := strings.ToLower(strings.TrimSpace(fileName))
	if n == "" {
		n = strings.ToLower(filepath.Base(p))
	}

	if isAlwaysSignal(p, n) {
		return ""
	}
	if isCaptureSelf(p, n) {
		return "capture"
	}
	if noiseNames[n] {
		return "os_telemetry"
	}
	for _, s := range noiseNameContains {
		if strings.Contains(n, s) {
			return "os_telemetry"
		}
	}
	if strings.HasSuffix(n, ".tmp") || strings.HasSuffix(n, ".etl") ||
		strings.HasSuffix(n, ".log") || strings.HasSuffix(n, ".wer") ||
		strings.HasSuffix(n, ".dmp") || strings.HasSuffix(n, ".pf") {
		return "os_telemetry"
	}

	for _, part := range captureSelfParts {
		if strings.Contains(p, part) {
			return "capture"
		}
	}
	for _, part := range browserCacheParts {
		if strings.Contains(p, strings.ToLower(part)) {
			return "browser_cache"
		}
	}
	for _, part := range noisePathParts {
		if strings.Contains(p, part) {
			if strings.Contains(p, `\windows\temp\`) || strings.Contains(p, `\appdata\local\temp\`) {
				return "temp"
			}
			if strings.Contains(p, `\wer\`) || strings.Contains(p, `reportqueue`) {
				return "wer"
			}
			return "os_telemetry"
		}
	}
	return ""
}

func isCaptureSelf(p, n string) bool {
	if strings.HasPrefix(n, "hklm-") && (strings.HasSuffix(n, ".reg") || strings.HasSuffix(n, ".json")) {
		return true
	}
	return strings.Contains(p, `\users\public\quarantine\`)
}

func isAlwaysSignal(p, n string) bool {
	if n == "hosts" || n == "lmhosts" || n == "networks" || n == "protocol" || n == "services" {
		return true
	}
	ext := filepath.Ext(n)
	if signalExt[ext] {
		// Recent .lnk is Explorer noise; Start Menu / Startup .lnk is persistence.
		if ext == ".lnk" && strings.Contains(p, `\recent\`) {
			return false
		}
		return true
	}
	if strings.Contains(p, `\windows\system32\drivers\etc\`) {
		return true
	}
	if strings.Contains(p, `\windows\system32\drivers\`) && !strings.Contains(p, `\etc\`) {
		return true
	}
	if isSystem32SignalPath(p) {
		return true
	}
	if strings.Contains(p, `\windows\syswow64\`) && !strings.Contains(p, `\appdata\`) {
		// SysWOW64 root / known persistence dirs, not nested telemetry.
		if !strings.Contains(p, `\config\systemprofile\`) && !strings.Contains(p, `\spp\store\`) {
			return true
		}
	}
	if strings.Contains(p, `\start menu\programs\startup\`) ||
		strings.Contains(p, `\windows\system32\tasks\`) ||
		strings.Contains(p, `\windows\tasks\`) {
		return true
	}
	return false
}

func isSystem32SignalPath(p string) bool {
	idx := strings.Index(p, `\windows\system32\`)
	if idx < 0 {
		return false
	}
	rest := p[idx+len(`\windows\system32\`):]
	if rest == "" {
		return false
	}
	// Hide known telemetry under System32; keep anything else (root files, drivers, etc).
	if strings.HasPrefix(rest, `config\systemprofile\`) ||
		strings.HasPrefix(rest, `spp\store\`) ||
		strings.HasPrefix(rest, `winevt\logs\`) ||
		strings.HasPrefix(rest, `wbem\repository\`) ||
		strings.HasPrefix(rest, `config\journal\`) ||
		strings.HasPrefix(rest, `config\txr\`) {
		return false
	}
	return true
}

// FilePriority ranks a path for inclusion when a list must be capped (lower = keep first).
func FilePriority(path string) int {
	p := strings.ToLower(strings.ReplaceAll(filepath.Clean(path), "/", `\`))
	n := strings.ToLower(filepath.Base(p))
	if n == "hosts" || strings.Contains(p, `\drivers\etc\`) {
		return 0
	}
	if isSystem32SignalPath(p) || strings.Contains(p, `\windows\syswow64\`) {
		return 0
	}
	if strings.Contains(p, `\program files\`) || strings.Contains(p, `\program files (x86)\`) {
		return 1
	}
	if strings.Contains(p, `\startup\`) || strings.Contains(p, `\windows\system32\tasks\`) {
		return 1
	}
	if signalExt[filepath.Ext(n)] {
		return 2
	}
	if strings.Contains(p, `\users\`) &&
		(strings.Contains(p, `\desktop\`) || strings.Contains(p, `\documents\`) ||
			strings.Contains(p, `\downloads\`) || strings.Contains(p, `\pictures\`)) {
		return 3
	}
	return 4
}

func isCloseOnlyReason(reasons []string, reasonCode string) bool {
	code := strings.ToLower(strings.TrimSpace(reasonCode))
	if code == "0x80000000" || code == "0x00000000" {
		return true
	}
	if len(reasons) == 1 {
		r := strings.ToLower(strings.ReplaceAll(reasons[0], " ", "_"))
		return r == "close" || r == "0x80000000"
	}
	return false
}
