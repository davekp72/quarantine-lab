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
func SyncExportPath() string       { return PublicDir + `\agent-token-sync.txt` }
func GuestControlUserFile() string { return DataDir + `\guestcontrol.user` }
func HiveRoot() string             { return DataDir + `\hives` }
func InstallScript() string        { return PublicDir + `\Install-QuarantineAgent.ps1` }
func InstallConfig() string        { return PublicDir + `\agent-install.json` }

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
