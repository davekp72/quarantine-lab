package guestpaths

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Guest Windows locations for the quarantine agent.
// Secrets and hive dumps must not live under C:\Users\Public.
const (
	InstallDir = `C:\Program Files\QuarantineLab`
	DataDir    = `C:\ProgramData\QuarantineLab`
	PublicDir  = `C:\Users\Public\Quarantine` // non-secret lab scripts / binary staging only
)

func InstallExe() string           { return InstallDir + `\quarantine-agent.exe` }
func TokenPath() string            { return DataDir + `\agent-token.txt` }
func ConfigPath() string           { return DataDir + `\agent.json` }
func LogPath() string              { return DataDir + `\agent.log` }
func StagingDir() string           { return PublicDir + `\agent-staging` }
func StagingTokenPath() string     { return StagingDir() + `\agent-token.txt` }
func StagingInstallScript() string { return StagingDir() + `\Install-QuarantineAgent.ps1` }
func StagingUpgradeScript() string { return StagingDir() + `\Upgrade-QuarantineAgent.ps1` }
func StagingInstallConfig() string { return StagingDir() + `\agent-install.json` }
func SyncExportPath() string       { return PublicDir + `\agent-token-sync.txt` }
func GuestControlUserFile() string { return DataDir + `\guestcontrol.user` }
func HiveRoot() string             { return DataDir + `\hives` }
func InstallScript() string        { return PublicDir + `\Install-QuarantineAgent.ps1` }
func InstallConfig() string        { return PublicDir + `\agent-install.json` }
func InboxDir() string             { return PublicDir + `\inbox` }
func DefaultSysmonDir() string     { return PublicDir + `\sysmon` }

// FileOp is an agent file-API operation.
type FileOp string

const (
	FileGet    FileOp = "get"
	FilePut    FileOp = "put"
	FileDelete FileOp = "delete"
)

// FilePolicy is the allowlist for /v1/files and /v1/exec.
type FilePolicy struct {
	PayloadUser string
	LabAdmin    string
	SysmonDir   string
}

// CanonWindows normalizes a guest path for prefix checks (no filesystem access).
func CanonWindows(p string) string {
	return canon(p)
}

// GuestJoin joins Windows guest path elements.
func GuestJoin(elem ...string) string {
	return strings.ReplaceAll(filepath.Join(elem...), `/`, `\`)
}

func (p FilePolicy) sysmonRoot() string {
	if strings.TrimSpace(p.SysmonDir) != "" {
		return canon(p.SysmonDir)
	}
	return canon(DefaultSysmonDir())
}

func (p FilePolicy) profileRoots() []string {
	var roots []string
	seen := map[string]bool{}
	for _, user := range []string{p.PayloadUser, p.LabAdmin} {
		user = strings.TrimSpace(user)
		if user == "" || strings.ContainsAny(user, `/\`) {
			continue
		}
		base := canon(`C:\Users\` + user)
		if seen[base] {
			continue
		}
		seen[base] = true
		roots = append(roots, base+`\desktop`, base+`\downloads`)
	}
	return roots
}

func under(n, root string) bool {
	return n == root || strings.HasPrefix(n, root+`\`)
}

// AllowedFile reports whether path may be used for op.
func (p FilePolicy) AllowedFile(path string, op FileOp) error {
	n := canon(path)
	if n == "" || n == `.` || strings.Contains(n, `..`) {
		return fmt.Errorf("invalid path")
	}
	if strings.HasPrefix(n, `\\`) {
		return fmt.Errorf("UNC paths are not allowed")
	}
	public := canon(PublicDir)
	switch op {
	case FileGet:
		if under(n, public) || under(n, p.sysmonRoot()) || IsHivePath(path) || n == canon(TokenPath()) {
			return nil
		}
		for _, r := range p.profileRoots() {
			if under(n, r) {
				return nil
			}
		}
		return fmt.Errorf("path not allowed for get")
	case FilePut, FileDelete:
		if IsProtectedRoot(path) {
			return fmt.Errorf("refusing to modify protected agent paths")
		}
		if under(n, public) || under(n, p.sysmonRoot()) {
			return nil
		}
		if op == FileDelete && ShouldDeleteHiveDir(path) {
			return nil
		}
		for _, r := range p.profileRoots() {
			if under(n, r) {
				return nil
			}
		}
		return fmt.Errorf("path not allowed for %s", op)
	default:
		return fmt.Errorf("unknown file op")
	}
}

// AllowedExec reports whether exe may be launched via /v1/exec.
func (p FilePolicy) AllowedExec(exe string) error {
	n := canon(exe)
	if n == "" || !strings.Contains(n, `:`) || strings.Contains(n, `..`) {
		return fmt.Errorf("exec path must be an absolute Windows path")
	}
	if strings.HasPrefix(n, `\\`) {
		return fmt.Errorf("UNC executables are not allowed")
	}
	if under(n, canon(`C:\Windows`)) {
		return nil
	}
	if err := p.AllowedFile(exe, FileGet); err == nil {
		return nil
	}
	return fmt.Errorf("executable path not allowed")
}

// TokenCopyCandidates are guest paths copyfrom may read before an elevated export.
func TokenCopyCandidates() []string {
	return []string{
		TokenPath(),
		StagingTokenPath(),
		LegacyPublicTokenPath(),
		PublicDir + `\agent-token.txt`,
	}
}

func HiveDir(snapshot string) string {
	return HiveRoot() + `\` + sanitize(snapshot)
}

// LegacyPublicTokenPath is the pre-1.0.15 token location (upgrade sync only).
func LegacyPublicTokenPath() string {
	return PublicDir + `\agent\agent-token.txt`
}

func LegacyPublicHiveRoot() string {
	return PublicDir + `\hives`
}

func IsHivePath(p string) bool {
	n := canon(p)
	root := canon(HiveRoot())
	return n == root || strings.HasPrefix(n, root+`\`)
}

// ShouldDeleteHiveDir is true for current ProgramData hive dirs and leftover Public dumps.
func ShouldDeleteHiveDir(p string) bool {
	if IsHivePath(p) {
		return true
	}
	n := canon(p)
	legacy := canon(LegacyPublicHiveRoot())
	return n == legacy || strings.HasPrefix(n, legacy+`\`)
}

// HiveFilePath joins a snapshot hive dir with a basename and rejects path traversal.
func HiveFilePath(snapshot, name string) (string, error) {
	base := filepath.Base(strings.TrimSpace(name))
	if base == "" || base == "." || base == ".." {
		return "", fmt.Errorf("invalid hive file name")
	}
	if strings.ContainsAny(name, `/\`) && filepath.Base(name) != strings.TrimSpace(name) {
		return "", fmt.Errorf("hive file name must be a basename")
	}
	p := HiveDir(snapshot) + `\` + base
	if !IsHivePath(p) {
		return "", fmt.Errorf("refusing hive path outside hive root")
	}
	return p, nil
}

func IsProtectedRoot(p string) bool {
	n := canon(p)
	data := canon(DataDir)
	inst := canon(InstallDir)
	return n == data || strings.HasPrefix(n, data+`\`) || n == inst || strings.HasPrefix(n, inst+`\`)
}

func canon(p string) string {
	p = strings.TrimSpace(p)
	p = strings.ReplaceAll(p, `/`, `\`)
	p = filepath.Clean(p)
	p = strings.ToLower(p)
	return strings.TrimRight(p, `\`)
}

func sanitize(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "snap"
	}
	return strings.Map(func(r rune) rune {
		switch r {
		case ':', '/', '\\', '*', '?', '"', '<', '>', '|', ' ':
			return '_'
		default:
			return r
		}
	}, s)
}
