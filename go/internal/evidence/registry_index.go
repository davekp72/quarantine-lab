package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	registryIndexSuffix     = "-registry-index.jsonl.gz"
	registryIndexMetaSuffix = "-registry-meta.json"
	registryHivesDirSuffix  = "-hives"
)

// HiveFileRef is a host-local hive for index building.
type HiveFileRef struct {
	LocalPath string
	GuestPath string
	Prefix    string
}

// RegistryIndexPath returns the gzip JSONL hive index sidecar path.
func (s *Service) RegistryIndexPath(snapshotName string) string {
	return s.Cfg.SidecarPath(snapshotName, registryIndexSuffix)
}

// RegistryIndexMetaPath returns the hive index metadata sidecar path.
func (s *Service) RegistryIndexMetaPath(snapshotName string) string {
	return s.Cfg.SidecarPath(snapshotName, registryIndexMetaSuffix)
}

// RegistryHivesDir returns the host directory for pulled `reg save` hive files.
func (s *Service) RegistryHivesDir(snapshotName string) string {
	return s.Cfg.SidecarPath(snapshotName, registryHivesDirSuffix)
}

// HasRegistryIndex reports whether both index and meta exist.
func (s *Service) HasRegistryIndex(snapshotName string) bool {
	if _, err := os.Stat(s.RegistryIndexPath(snapshotName)); err != nil {
		return false
	}
	if _, err := os.Stat(s.RegistryIndexMetaPath(snapshotName)); err != nil {
		return false
	}
	return true
}

// InvalidateRegistryIndex removes index/meta so the next ensure rebuilds from hives/disk.
func (s *Service) InvalidateRegistryIndex(snapshotName string) {
	_ = os.Remove(s.RegistryIndexPath(snapshotName))
	_ = os.Remove(s.RegistryIndexMetaPath(snapshotName))
}

// RegistryHivesNewerThanIndex is true when a live hive dump exists and is newer than the index.
func (s *Service) RegistryHivesNewerThanIndex(snapshotName string) bool {
	if !s.HasRegistryHives(snapshotName) || !s.HasRegistryIndex(snapshotName) {
		return s.HasRegistryHives(snapshotName) && !s.HasRegistryIndex(snapshotName)
	}
	hiveDir, err := os.Stat(s.RegistryHivesDir(snapshotName))
	if err != nil {
		return false
	}
	idx, err := os.Stat(s.RegistryIndexPath(snapshotName))
	if err != nil {
		return true
	}
	return hiveDir.ModTime().After(idx.ModTime())
}

// HasRegistryHives reports whether live-pulled hive files exist for a snapshot.
func (s *Service) HasRegistryHives(snapshotName string) bool {
	files, err := s.ListRegistryHiveFiles(snapshotName)
	return err == nil && len(files) > 0
}

// ListRegistryHiveFiles returns host paths + prefixes for pulled hives.
func (s *Service) ListRegistryHiveFiles(snapshotName string) ([]HiveFileRef, error) {
	dir := s.RegistryHivesDir(snapshotName)
	manPath := filepath.Join(dir, "manifest.json")
	type fileEnt struct {
		Name      string `json:"name"`
		HostPath  string `json:"hostPath"`
		GuestPath string `json:"guestPath"`
		Prefix    string `json:"prefix"`
	}
	type man struct {
		Files []fileEnt `json:"files"`
	}
	var out []HiveFileRef
	if raw, err := os.ReadFile(manPath); err == nil {
		var m man
		if json.Unmarshal(raw, &m) == nil && len(m.Files) > 0 {
			for _, f := range m.Files {
				p := f.HostPath
				if p == "" {
					p = filepath.Join(dir, f.Name)
				}
				out = append(out, HiveFileRef{LocalPath: p, GuestPath: f.GuestPath, Prefix: f.Prefix})
			}
			return out, nil
		}
	}
	known := map[string]string{
		"SOFTWARE": `HKLM:\SOFTWARE`,
		"SYSTEM":   `HKLM:\SYSTEM`,
		"DEFAULT":  `HKU:\.DEFAULT`,
		"SAM":      `HKLM:\SAM`,
		"SECURITY": `HKLM:\SECURITY`,
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		if e.IsDir() || e.Name() == "manifest.json" {
			continue
		}
		prefix := known[e.Name()]
		if prefix == "" && strings.HasPrefix(e.Name(), "NTUSER_") {
			sid := strings.TrimPrefix(e.Name(), "NTUSER_")
			prefix = `HKU:\` + sid
		}
		if prefix == "" {
			continue
		}
		out = append(out, HiveFileRef{
			LocalPath: filepath.Join(dir, e.Name()),
			GuestPath: e.Name(),
			Prefix:    prefix,
		})
	}
	return out, nil
}

// RegistryIndexWorkDir returns a temp work directory for hive extraction.
func (s *Service) RegistryIndexWorkDir(snapshotName string) string {
	return filepath.Join(os.TempDir(), "quarantine-lab", "hives", registrySafeName(snapshotName))
}

// EnsureRegistryIndexDir prepares a clean work directory for hive extraction.
func (s *Service) EnsureRegistryIndexDir(snapshotName string) (string, error) {
	workDir := s.RegistryIndexWorkDir(snapshotName)
	_ = os.RemoveAll(workDir)
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return "", fmt.Errorf("hive work dir: %w", err)
	}
	return workDir, nil
}

func registrySafeName(s string) string {
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
