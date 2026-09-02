package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/guest"
	"github.com/quarantine-lab/quarantine/internal/jsonutil"
	"github.com/quarantine-lab/quarantine/internal/vbox"
)

// Manifest is the canonical snapshot manifest JSON.
type Manifest struct {
	Snapshot           string          `json:"snapshot"`
	CapturedAt         string          `json:"capturedAt"`
	Version            int             `json:"version"`
	ScanMode           string          `json:"scanMode"`
	RegistryEngine     string          `json:"registryEngine"`
	ComputerName       string          `json:"computerName"`
	FileCount          int             `json:"fileCount"`
	RegistryCount      int             `json:"registryCount"`
	UserRegistryCount  int             `json:"userRegistryCount"`
	Files              []FileEntry     `json:"files"`
	Registry           []RegistryEntry `json:"registry"`
	Tasks              []TaskEntry     `json:"tasks"`
	USN                json.RawMessage `json:"usn,omitempty"`
	Sysmon             json.RawMessage `json:"sysmon,omitempty"`
	ServiceInstalls    json.RawMessage `json:"serviceInstalls,omitempty"`
	UserRegistryWarn   []string        `json:"userRegistryWarnings,omitempty"`
}

type FileEntry struct {
	P      string `json:"p"`
	Path   string `json:"path,omitempty"`
	S      int64  `json:"s,omitempty"`
	H      string `json:"h,omitempty"`
	M      string `json:"m,omitempty"`
	Src    string `json:"src,omitempty"`
	Change string `json:"change,omitempty"`
	C      string `json:"c,omitempty"`
	D      string `json:"d,omitempty"`
}

func (f FileEntry) PathValue() string {
	if f.P != "" {
		return f.P
	}
	return f.Path
}

type RegistryEntry struct {
	K string `json:"k"`
	N string `json:"n"`
	T string `json:"t"`
	V any    `json:"v"`
}

type TaskEntry map[string]any

// Service manages evidence sidecars and manifests.
type Service struct {
	Cfg        *config.Config
	VBox       *vbox.Client
	Guest      *guest.Client
	ConfigPath string
	ProjectRoot string
}

// NewService creates evidence service.
func NewService(cfgPath string) (*Service, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}
	vb, err := vbox.NewClient(cfg.VBoxManagePath)
	if err != nil {
		return nil, err
	}
	return &Service{
		Cfg:         cfg,
		VBox:        vb,
		Guest:       guest.New(cfg, vb),
		ConfigPath:  cfgPath,
		ProjectRoot: config.ProjectRoot(cfgPath),
	}, nil
}

// LoadManifest reads manifest JSON for a snapshot.
func (s *Service) LoadManifest(snapshotName string) (*Manifest, error) {
	path := s.Cfg.ManifestPath(snapshotName)
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest %s: %w", path, err)
	}
	return ParseManifestJSON(raw)
}

// ParseManifestJSON parses manifest bytes (first JSON value only).
func ParseManifestJSON(raw []byte) (*Manifest, error) {
	dec := json.NewDecoder(bytes.NewReader(jsonutil.StripBOM(raw)))
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

// LoadSidecar reads arbitrary sidecar JSON into a generic map.
func (s *Service) LoadSidecar(snapshotName, suffix string) (map[string]any, error) {
	path := s.Cfg.SidecarPath(snapshotName, suffix)
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := jsonutil.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// PublishFromSidecars builds/updates manifest from live sidecars on disk.
// If the payload sidecar is missing but a manifest already exists, returns that path unchanged.
// When only a USN baseline exists, marker sidecars and a minimal manifest are synthesized.
func (s *Service) PublishFromSidecars(snapshotName string) (string, error) {
	snap := s.Cfg.ResolveSnapshotName(snapshotName)
	hostPath := s.Cfg.ManifestPath(snap)

	payload, err := s.LoadSidecar(snap, "-payload-registry.json")
	if err != nil {
		if _, statErr := os.Stat(hostPath); statErr == nil {
			return hostPath, nil
		}
		if s.hasAnyCaptureSidecar(snap) {
			_ = s.ensurePayloadSidecar(snap)
			if payload, loadErr := s.LoadSidecar(snap, "-payload-registry.json"); loadErr == nil {
				return s.writeManifestFromSidecars(snap, hostPath, payload)
			}
		}
		if path, partialErr := s.publishFromPartialSidecars(snap, hostPath); partialErr == nil {
			return path, nil
		}
		return "", fmt.Errorf("payload registry sidecar missing for %s (launch snapshot, log in as payload user, retake snapshot or compare with Refresh while VM is running): %w", snap, err)
	}

	return s.writeManifestFromSidecars(snap, hostPath, payload)
}

func (s *Service) publishFromPartialSidecars(snap, hostPath string) (string, error) {
	if !s.hasAnyCaptureSidecar(snap) {
		return "", fmt.Errorf("no capture sidecars on disk")
	}
	baselinePath := s.Cfg.SidecarPath(snap, "-baseline.json")
	if _, err := os.Stat(baselinePath); err == nil {
		_ = s.saveBaselineEventMarkerSidecars(snap)
	}

	m := &Manifest{
		Snapshot:       snap,
		CapturedAt:     time.Now().UTC().Format(time.RFC3339),
		ScanMode:       s.Cfg.Manifest.ScanMode,
		RegistryEngine: s.Cfg.Manifest.RegistryEngine,
		Version:        5,
		Files:          []FileEntry{},
		Registry:       []RegistryEntry{},
		Tasks:          []TaskEntry{},
	}
	if raw, err := os.ReadFile(baselinePath); err == nil {
		var baseline map[string]any
		if jsonutil.Unmarshal(raw, &baseline) == nil {
			if v, ok := baseline["recordedAt"].(string); ok {
				m.CapturedAt = v
			}
			if v, ok := baseline["computer"].(string); ok {
				m.ComputerName = v
			}
		}
	} else if hklm, err := s.LoadSidecar(snap, "-hklm-registry.json"); err == nil {
		if v, ok := hklm["capturedAt"].(string); ok {
			m.CapturedAt = v
		}
	}
	if hklm, err := s.LoadSidecar(snap, "-hklm-registry.json"); err == nil {
		if reg, ok := hklm["registry"].([]any); ok {
			for _, item := range reg {
				if rm, ok := item.(map[string]any); ok {
					entry := RegistryEntry{}
					if k, ok := rm["k"].(string); ok {
						entry.K = k
					}
					if n, ok := rm["n"].(string); ok {
						entry.N = n
					}
					if t, ok := rm["t"].(string); ok {
						entry.T = t
					}
					entry.V = rm["v"]
					m.Registry = append(m.Registry, entry)
				}
			}
			m.RegistryCount = len(m.Registry)
		}
	}
	if usn, err := os.ReadFile(s.Cfg.SidecarPath(snap, "-usn-delta.json")); err == nil {
		m.USN = usn
	}
	if sysmon, err := os.ReadFile(s.Cfg.SidecarPath(snap, "-sysmon.json")); err == nil {
		m.Sysmon = sysmon
	}
	if svc, err := os.ReadFile(s.Cfg.SidecarPath(snap, "-service-installs.json")); err == nil {
		m.ServiceInstalls = svc
	}
	if changed, err := s.LoadSidecar(snap, "-changed-files.json"); err == nil {
		if files, ok := changed["files"].([]any); ok {
			for _, item := range files {
				if fm, ok := item.(map[string]any); ok {
					fe := FileEntry{}
					if p, ok := fm["p"].(string); ok {
						fe.P = p
					}
					m.Files = append(m.Files, fe)
				}
			}
			m.FileCount = len(m.Files)
		}
	}

	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(hostPath, raw, 0o644); err != nil {
		return "", err
	}
	return hostPath, nil
}

func (s *Service) writeManifestFromSidecars(snap, hostPath string, payload map[string]any) (string, error) {
	m := &Manifest{
		Snapshot:       snap,
		ScanMode:       s.Cfg.Manifest.ScanMode,
		RegistryEngine: s.Cfg.Manifest.RegistryEngine,
		Version:        5,
		Files:          []FileEntry{},
		Registry:       []RegistryEntry{},
		Tasks:          []TaskEntry{},
	}
	if v, ok := payload["capturedAt"].(string); ok {
		m.CapturedAt = v
	}
	if v, ok := payload["computerName"].(string); ok {
		m.ComputerName = v
	}
	if reg, ok := payload["registry"].([]any); ok {
		for _, item := range reg {
			if rm, ok := item.(map[string]any); ok {
				entry := RegistryEntry{}
				if k, ok := rm["k"].(string); ok {
					entry.K = k
				}
				if n, ok := rm["n"].(string); ok {
					entry.N = n
				}
				if t, ok := rm["t"].(string); ok {
					entry.T = t
				}
				entry.V = rm["v"]
				m.Registry = append(m.Registry, entry)
			}
		}
	}
	m.RegistryCount = len(m.Registry)

	if changed, err := s.LoadSidecar(snap, "-changed-files.json"); err == nil {
		if files, ok := changed["files"].([]any); ok {
			for _, item := range files {
				if fm, ok := item.(map[string]any); ok {
					fe := FileEntry{}
					if p, ok := fm["p"].(string); ok {
						fe.P = p
					}
					m.Files = append(m.Files, fe)
				}
			}
			m.FileCount = len(m.Files)
		}
	}

	if usn, err := os.ReadFile(s.Cfg.SidecarPath(snap, "-usn-delta.json")); err == nil {
		m.USN = usn
	}
	if sysmon, err := os.ReadFile(s.Cfg.SidecarPath(snap, "-sysmon.json")); err == nil {
		m.Sysmon = sysmon
	}
	if svc, err := os.ReadFile(s.Cfg.SidecarPath(snap, "-service-installs.json")); err == nil {
		m.ServiceInstalls = svc
	}

	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(hostPath, raw, 0o644); err != nil {
		return "", err
	}
	return hostPath, nil
}

// DeployGuestScripts copies manifest PS scripts to guest (legacy fallback when agent.enabled is false).
func (s *Service) DeployGuestScripts() error {
	if s.Cfg.Agent.Enabled {
		return fmt.Errorf("guest script deploy is legacy; use quarantine agent install with agent.enabled=true")
	}
	manifestDir := filepath.Join(s.ProjectRoot, "manifest")
	scripts := []string{
		"Get-QuarantineGuestUsnDelta.ps1",
		"Get-QuarantineGuestSysmonEvents.ps1",
		"Export-QuarantineGuestPayloadRegistryCli.ps1",
		"Export-QuarantineGuestHklmRegistryCli.ps1",
		"Export-QuarantineGuestChangedFiles.ps1",
		"Get-QuarantineGuestServiceInstallEvents.ps1",
		"Set-QuarantineGuestUsnBaseline.ps1",
	}
	creds := s.Guest.GuestCreds()
	for _, name := range scripts {
		host := filepath.Join(manifestDir, name)
		if _, err := os.Stat(host); err != nil {
			continue
		}
		if err := s.Guest.CopyTo(host, s.Cfg.Guest.CopyTargetDir, creds); err != nil {
			return fmt.Errorf("deploy %s: %w", name, err)
		}
	}
	return nil
}

func (s *Service) hasAnyCaptureSidecar(snap string) bool {
	for _, suffix := range []string{
		"-baseline.json", "-usn-delta.json", "-sysmon.json", "-hklm-registry.json",
		"-changed-files.json", "-service-installs.json",
	} {
		if _, err := os.Stat(s.Cfg.SidecarPath(snap, suffix)); err == nil {
			return true
		}
	}
	return false
}

func (s *Service) ensurePayloadSidecar(snap string) error {
	path := s.Cfg.SidecarPath(snap, "-payload-registry.json")
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	capturedAt := time.Now().UTC().Format(time.RFC3339)
	if hklm, err := s.LoadSidecar(snap, "-hklm-registry.json"); err == nil {
		if v, ok := hklm["capturedAt"].(string); ok && v != "" {
			capturedAt = v
		}
	}
	payload := map[string]any{
		"engine":     "cli",
		"capturedAt": capturedAt,
		"snapshot":   snap,
		"entryCount": 0,
		"registry":   []any{},
		"warnings":   []string{"HKCU not captured — empty payload registry synthesized at publish time"},
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

// DiffOutputPath returns standard diff JSON path for a snapshot pair.
func (s *Service) DiffOutputPath(fromSnap, toSnap string) string {
	from := config.SafeSnapshotFileName(fromSnap)
	to := config.SafeSnapshotFileName(toSnap)
	return filepath.Join(s.Cfg.ManifestLogDir(), fmt.Sprintf("diff-%s-vs-%s.diff.json", from, to))
}

// RemoveSnapshotArtifacts deletes host-side manifest JSON, sidecars, and related diff files.
func (s *Service) RemoveSnapshotArtifacts(snapshotName string) []string {
	logDir := s.Cfg.ManifestLogDir()
	if logDir == "" {
		return nil
	}
	safe := config.SafeSnapshotFileName(snapshotName)
	var removed []string

	files := []string{
		s.Cfg.ManifestPath(snapshotName),
		s.Cfg.SidecarPath(snapshotName, "-baseline.json"),
		s.Cfg.SidecarPath(snapshotName, "-payload-registry.json"),
		s.Cfg.SidecarPath(snapshotName, "-hklm-registry.json"),
		s.Cfg.SidecarPath(snapshotName, "-usn-delta.json"),
		s.Cfg.SidecarPath(snapshotName, "-sysmon.json"),
		s.Cfg.SidecarPath(snapshotName, "-service-installs.json"),
		s.Cfg.SidecarPath(snapshotName, "-changed-files.json"),
		filepath.Join(logDir, safe+"-regshot.hivu"),
		filepath.Join(logDir, safe+"-regshot-compare.txt"),
	}
	for _, path := range files {
		if err := os.Remove(path); err == nil {
			removed = append(removed, path)
		}
	}

	dirs := []string{
		s.Cfg.SidecarPath(snapshotName, "-payload-registry"),
		s.Cfg.SidecarPath(snapshotName, "-hklm-registry"),
	}
	for _, dir := range dirs {
		if err := os.RemoveAll(dir); err == nil {
			removed = append(removed, dir)
		}
	}

	staging, _ := filepath.Glob(filepath.Join(logDir, safe+".json.staging-*.json"))
	for _, path := range staging {
		if err := os.Remove(path); err == nil {
			removed = append(removed, path)
		}
	}

	diffPatterns := []string{
		filepath.Join(logDir, "diff-*-vs-"+safe+".diff.json"),
		filepath.Join(logDir, "diff-"+safe+"-vs-*.diff.json"),
	}
	for _, pattern := range diffPatterns {
		matches, _ := filepath.Glob(pattern)
		for _, path := range matches {
			if err := os.Remove(path); err == nil {
				removed = append(removed, path)
			}
		}
	}
	return removed
}
