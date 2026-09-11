package evidence

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/guest"
	"github.com/quarantine-lab/quarantine/internal/jsonutil"
	"github.com/quarantine-lab/quarantine/internal/vbox"
)

// Manifest is the canonical snapshot manifest JSON.
type Manifest struct {
	Snapshot          string          `json:"snapshot"`
	CapturedAt        string          `json:"capturedAt"`
	Version           int             `json:"version"`
	ScanMode          string          `json:"scanMode"`
	RegistryEngine    string          `json:"registryEngine"`
	ComputerName      string          `json:"computerName"`
	FileCount         int             `json:"fileCount"`
	RegistryCount     int             `json:"registryCount"`
	UserRegistryCount int             `json:"userRegistryCount"`
	Files             []FileEntry     `json:"files"`
	Registry          []RegistryEntry `json:"registry"`
	Tasks             []TaskEntry     `json:"tasks"`
	USN               json.RawMessage `json:"usn,omitempty"`
	Sysmon            json.RawMessage `json:"sysmon,omitempty"`
	ServiceInstalls   json.RawMessage `json:"serviceInstalls,omitempty"`
	UserRegistryWarn  []string        `json:"userRegistryWarnings,omitempty"`
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

func fileEntryFromChangedMap(fm map[string]any) FileEntry {
	fe := FileEntry{}
	if p, ok := fm["p"].(string); ok {
		fe.P = p
	}
	if s, ok := fm["s"].(float64); ok {
		fe.S = int64(s)
	}
	if h, ok := fm["h"].(string); ok {
		fe.H = h
	}
	if mtime, ok := fm["m"].(string); ok {
		fe.M = mtime
	}
	if src, ok := fm["src"].(string); ok {
		fe.Src = src
	}
	if ch, ok := fm["change"].(string); ok {
		fe.Change = ch
	}
	return fe
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
	Cfg         *config.Config
	VBox        *vbox.Client
	Guest       *guest.Client
	ConfigPath  string
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

// FileContentFromSidecar returns captured file bytes from changed-files sidecar when available.
func (s *Service) FileContentFromSidecar(snapshotName, guestPath string) ([]byte, bool) {
	entry, ok := s.FileSidecarEntry(snapshotName, guestPath)
	if !ok {
		return nil, false
	}
	return FileSidecarContent(entry)
}

// FileSidecarContent returns captured bytes from a changed-files sidecar row.
func FileSidecarContent(entry map[string]any) ([]byte, bool) {
	if entry == nil {
		return nil, false
	}
	d, _ := entry["d"].(string)
	switch strings.ToLower(stringField(entry, "c")) {
	case "base64":
		if d == "" {
			return nil, false
		}
		raw, err := base64.StdEncoding.DecodeString(d)
		if err != nil {
			return nil, false
		}
		return raw, true
	case "text":
		return []byte(d), true
	case "too_large", "access_denied":
		return nil, false
	}
	if d != "" {
		return []byte(d), true
	}
	return nil, false
}

// FileSidecarSize returns the guest file size recorded on a changed-files sidecar row.
func FileSidecarSize(entry map[string]any) int64 {
	if entry == nil {
		return 0
	}
	for _, key := range []string{"s", "size"} {
		if n := jsonInt64(entry[key]); n > 0 {
			return n
		}
	}
	return 0
}

func stringField(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func jsonInt64(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	default:
		return 0
	}
}

// FileCreateMeta holds Sysmon FileCreate context for a guest path.
type FileCreateMeta struct {
	Time  string `json:"time,omitempty"`
	Image string `json:"image,omitempty"`
	EID   int    `json:"eid,omitempty"`
}

// FileSidecarEntry returns the changed-files sidecar row for a guest path when present.
func (s *Service) FileSidecarEntry(snapshotName, guestPath string) (map[string]any, bool) {
	snap := s.Cfg.ResolveSnapshotName(snapshotName)
	sc, err := s.LoadSidecar(snap, "-changed-files.json")
	if err != nil {
		return nil, false
	}
	files, _ := sc["files"].([]any)
	want := strings.ToLower(filepath.Clean(guestPath))
	for _, item := range files {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		p, _ := m["p"].(string)
		if p == "" {
			p, _ = m["path"].(string)
		}
		if strings.ToLower(filepath.Clean(p)) == want {
			return m, true
		}
	}
	return nil, false
}

// FileCapturedInSidecar reports whether changed-files sidecar captured bytes or a hash.
func FileCapturedInSidecar(entry map[string]any) bool {
	if entry == nil {
		return false
	}
	if d, ok := entry["d"].(string); ok && d != "" {
		return true
	}
	if h, ok := entry["h"].(string); ok && h != "" {
		return true
	}
	if hash, ok := entry["hash"].(string); ok && hash != "" {
		return true
	}
	return false
}

// FileCreateMetaFromSysmon returns the newest Sysmon FileCreate event for a path.
func (s *Service) FileCreateMetaFromSysmon(snapshotName, guestPath string) *FileCreateMeta {
	snap := s.Cfg.ResolveSnapshotName(snapshotName)
	raw, err := os.ReadFile(s.Cfg.SidecarPath(snap, "-sysmon.json"))
	if err != nil {
		return nil
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	events, _ := doc["events"].([]any)
	want := strings.ToLower(filepath.Clean(guestPath))
	var best *FileCreateMeta
	for _, item := range events {
		ev, ok := item.(map[string]any)
		if !ok {
			continue
		}
		eid, _ := ev["eid"].(float64)
		if int(eid) != 11 {
			continue
		}
		target, _ := ev["target"].(string)
		if target == "" {
			target, _ = ev["targetFilename"].(string)
		}
		if strings.ToLower(filepath.Clean(target)) != want {
			continue
		}
		meta := &FileCreateMeta{
			Time:  stringFromAny(ev["time"]),
			Image: stringFromAny(ev["image"]),
			EID:   11,
		}
		if best == nil || meta.Time > best.Time {
			best = meta
		}
	}
	return best
}

func stringFromAny(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
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
					m.Files = append(m.Files, fileEntryFromChangedMap(fm))
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
	m.UserRegistryCount = 0
	for _, e := range m.Registry {
		u := strings.ToUpper(e.K)
		if strings.HasPrefix(u, `HKU\`) || strings.HasPrefix(u, `HKU:`) {
			m.UserRegistryCount++
		}
	}
	if warns, ok := payload["warnings"].([]any); ok {
		for _, w := range warns {
			if s, ok := w.(string); ok && strings.TrimSpace(s) != "" {
				m.UserRegistryWarn = append(m.UserRegistryWarn, s)
			}
		}
	}
	if m.UserRegistryCount == 0 {
		if rawWarns, ok := payload["warnings"].([]string); ok {
			m.UserRegistryWarn = append(m.UserRegistryWarn, rawWarns...)
		}
	}
	// Empty payload registry with an explicit capture error → mark as failed HKCU.
	if m.UserRegistryCount == 0 && len(m.UserRegistryWarn) == 0 {
		if ec, ok := payload["entryCount"].(float64); ok && ec == 0 {
			if sid, _ := payload["sid"].(string); sid == "" {
				m.UserRegistryWarn = append(m.UserRegistryWarn,
					"HKCU not captured (empty payload registry)")
			}
		}
	}

	// Merge machine registry (HKLM + shared HKU/.DEFAULT) into the manifest for diffs.
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
					if entry.K == "" {
						continue
					}
					m.Registry = append(m.Registry, entry)
				}
			}
		}
	}
	m.RegistryCount = len(m.Registry)
	m.UserRegistryCount = 0
	for _, e := range m.Registry {
		u := strings.ToUpper(e.K)
		if strings.HasPrefix(u, `HKU\`) || strings.HasPrefix(u, `HKU:`) {
			m.UserRegistryCount++
		}
	}

	if changed, err := s.LoadSidecar(snap, "-changed-files.json"); err == nil {
		if files, ok := changed["files"].([]any); ok {
			for _, item := range files {
				if fm, ok := item.(map[string]any); ok {
					m.Files = append(m.Files, fileEntryFromChangedMap(fm))
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
		"engine":     "hive",
		"capturedAt": capturedAt,
		"snapshot":   snap,
		"entryCount": 0,
		"registry":   []any{},
		"warnings":   []string{"Registry compare uses hive-index dumps; empty payload sidecar synthesized at publish time"},
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

// NetworkArtifactsDir returns the snapshot-scoped network evidence folder.
func (s *Service) NetworkArtifactsDir(snapshotName string) string {
	return s.Cfg.SidecarPath(snapshotName, "-network")
}

// AttachNetworkArtifacts moves host PCAP/proxy files into {Safe}-network/ for a preserve snapshot.
// Source files/dirs are removed after a successful move so flat logs/ do not keep orphans.
func (s *Service) AttachNetworkArtifacts(snapshotName, pcapPath, proxyDir string) (string, error) {
	if strings.TrimSpace(snapshotName) == "" {
		return "", fmt.Errorf("snapshot name required")
	}
	pcapPath = strings.TrimSpace(pcapPath)
	proxyDir = strings.TrimSpace(proxyDir)
	if pcapPath == "" && proxyDir == "" {
		return "", nil
	}

	dest := s.NetworkArtifactsDir(snapshotName)
	_ = os.RemoveAll(dest)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return "", err
	}

	meta := map[string]any{
		"snapshot":   snapshotName,
		"attachedAt": time.Now().UTC().Format(time.RFC3339),
	}

	if pcapPath != "" {
		if st, err := os.Stat(pcapPath); err == nil && !st.IsDir() {
			destPcap := filepath.Join(dest, "capture.pcap")
			if err := moveFile(pcapPath, destPcap); err != nil {
				return dest, fmt.Errorf("attach pcap: %w", err)
			}
			meta["pcap"] = "capture.pcap"
			meta["pcapBytes"] = st.Size()
			meta["pcapSource"] = filepath.Base(pcapPath)
		}
	}

	if proxyDir != "" {
		if st, err := os.Stat(proxyDir); err == nil && st.IsDir() {
			copied := 0
			for _, name := range []string{
				"access.log", "errors.log", "access-transparent.log",
				"flows.jsonl", "flows.mitm",
				"flows-transparent.jsonl", "flows-transparent.mitm",
			} {
				src := filepath.Join(proxyDir, name)
				if st, err := os.Stat(src); err != nil || st.IsDir() {
					continue
				}
				if err := moveFile(src, filepath.Join(dest, name)); err != nil {
					return dest, fmt.Errorf("attach %s: %w", name, err)
				}
				copied++
				if name == "flows.jsonl" {
					meta["flows"] = "flows.jsonl"
				}
				if name == "flows.mitm" {
					meta["flowsMitm"] = "flows.mitm"
				}
			}
			meta["proxyFiles"] = copied
			meta["proxySource"] = filepath.Base(proxyDir)
			_ = os.RemoveAll(proxyDir)
		}
	}

	raw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return dest, err
	}
	if err := os.WriteFile(filepath.Join(dest, "meta.json"), raw, 0o644); err != nil {
		return dest, err
	}
	return dest, nil
}

func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(dst)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(dst)
		return closeErr
	}
	return os.Remove(src)
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
		s.Cfg.SidecarPath(snapshotName, "-registry-index.jsonl.gz"),
		s.Cfg.SidecarPath(snapshotName, "-registry-meta.json"),
	}
	for _, path := range files {
		if err := os.Remove(path); err == nil {
			removed = append(removed, path)
		}
	}

	dirs := []string{
		s.Cfg.SidecarPath(snapshotName, "-payload-registry"),
		s.Cfg.SidecarPath(snapshotName, "-hklm-registry"),
		s.Cfg.SidecarPath(snapshotName, "-hives"),
		s.Cfg.SidecarPath(snapshotName, "-network"),
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
