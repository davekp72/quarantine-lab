package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config mirrors config/quarantine-vm.json.
type Config struct {
	VMName           string         `json:"vmName"`
	GuestOSType      string         `json:"guestOsType"`
	MemoryMB         int            `json:"memoryMb"`
	CPUCount         int            `json:"cpuCount"`
	DiskSizeGB       int            `json:"diskSizeGb"`
	VMDataDir        string         `json:"vmDataDir"`
	DiskPath         string         `json:"diskPath"`
	WindowsISOPath   string         `json:"windowsIsoPath"`
	AutounattendPath string         `json:"autounattendPath"`
	VBoxManagePath   string         `json:"vboxManagePath"`
	Network          NetworkConfig  `json:"network"`
	Isolation        IsolationConfig `json:"isolation"`
	Inbox            InboxConfig    `json:"inbox"`
	Guest            AccountConfig  `json:"guest"`
	Payload          AccountConfig  `json:"payload"`
	Sysmon           SysmonConfig   `json:"sysmon"`
	CleanSnapshot    string         `json:"cleanSnapshotName"`
	Firmware         string         `json:"firmware"`
	Manifest         ManifestConfig `json:"manifest"`
	Regshot          RegshotConfig  `json:"regshot"`
	Agent            AgentConfig    `json:"agent"`
}

type AgentConfig struct {
	Enabled         bool   `json:"enabled"`
	Host            string `json:"host"`
	Port            int    `json:"port"`
	Token           string `json:"token"`
	TokenFile       string `json:"tokenFile"`
	NatRuleName     string `json:"natRuleName"`
	InstallPath     string `json:"installPath"`
	HostBinaryPath  string `json:"hostBinaryPath"`
}

type NetworkConfig struct {
	Mode            string         `json:"mode"`
	HostOnlyAdapter string         `json:"hostOnlyAdapter"`
	IntnetName      string         `json:"intnetName"`
	GuestGateway    string         `json:"guestGateway"`
	GuestDNS        string         `json:"guestDns"`
	Proxy           ProxyConfig    `json:"proxy"`
	Capture         CaptureConfig  `json:"capture"`
}

type ProxyConfig struct {
	Enabled    bool   `json:"enabled"`
	ListenHost string `json:"listenHost"`
	ListenPort int    `json:"listenPort"`
	PACPort    int    `json:"pacPort"`
	LogDir     string `json:"logDir"`
}

type CaptureConfig struct {
	Enabled   bool   `json:"enabled"`
	Mode      string `json:"mode"`
	LogDir    string `json:"logDir"`
	Interface string `json:"interface"`
	GuestIP   string `json:"guestIp"`
}

type IsolationConfig struct {
	DisableClipboard     bool   `json:"disableClipboard"`
	ClipboardMode        string `json:"clipboardMode"`
	DisableDragDrop      bool   `json:"disableDragDrop"`
	DisableUSB           bool   `json:"disableUsb"`
	DisableAudio         bool   `json:"disableAudio"`
	DisableSharedFolders bool   `json:"disableSharedFolders"`
}

type InboxConfig struct {
	HostPath          string `json:"hostPath"`
	ShareName         string `json:"shareName"`
	ReadOnly          bool   `json:"readOnly"`
	RequireNetworkOff bool   `json:"requireNetworkOff"`
	LogDir            string `json:"logDir"`
}

type AccountConfig struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	PasswordFile  string `json:"passwordFile"`
	Domain        string `json:"domain"`
	DefaultExe    string `json:"defaultExe"`
	CopyTargetDir string `json:"copyTargetDir"`
	TimeoutMs     int    `json:"timeoutMs"`
	Role          string `json:"role"`
}

type SysmonConfig struct {
	HostConfigPath  string `json:"hostConfigPath"`
	GuestDir        string `json:"guestDir"`
	GuestConfigName string `json:"guestConfigName"`
	GuestSysmonExe  string `json:"guestSysmonExe"`
	EventLog        string `json:"eventLog"`
}

type ManifestConfig struct {
	LogDir                  string `json:"logDir"`
	ScanMode                string `json:"scanMode"`
	RegistryEngine          string `json:"registryEngine"`
	RegistryDiskFlatten     bool   `json:"registryDiskFlatten"`
	SessionBaselineSnapshot string `json:"sessionBaselineSnapshot"`
	HashMaxMB               int    `json:"hashMaxMb"`
	ContentMaxKB            int    `json:"contentMaxKb"`
}

type RegshotConfig struct {
	GuestDir     string `json:"guestDir"`
	HostToolsDir string `json:"hostToolsDir"`
}

// Load reads and validates quarantine-vm.json.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if strings.TrimSpace(cfg.VMName) == "" {
		return nil, fmt.Errorf("vmName is required in config")
	}
	if cfg.VMDataDir == "" {
		cfg.VMDataDir = `D:\Vbox\LabVM`
	}
	if cfg.CleanSnapshot == "" {
		cfg.CleanSnapshot = "Clean"
	}
	if cfg.Manifest.SessionBaselineSnapshot == "" {
		cfg.Manifest.SessionBaselineSnapshot = "CleanSession"
	}
	if cfg.Manifest.ScanMode == "" {
		cfg.Manifest.ScanMode = "events"
	}
	if cfg.Manifest.RegistryEngine == "" {
		cfg.Manifest.RegistryEngine = "hive"
	}
	if cfg.Guest.CopyTargetDir == "" {
		cfg.Guest.CopyTargetDir = `C:\Users\Public\Quarantine`
	}
	if cfg.Payload.CopyTargetDir == "" {
		cfg.Payload.CopyTargetDir = cfg.Guest.CopyTargetDir
	}
	if cfg.Agent.Port <= 0 {
		cfg.Agent.Port = 9443
	}
	if cfg.Agent.Host == "" {
		cfg.Agent.Host = "127.0.0.1"
	}
	if cfg.Agent.NatRuleName == "" {
		cfg.Agent.NatRuleName = "quarantine-agent"
	}
	if cfg.Agent.InstallPath == "" {
		cfg.Agent.InstallPath = cfg.AgentGuestInstallPath()
	}
	return &cfg, nil
}

// AgentGuestInstallPath returns a guest path writable by the lab admin account.
func (c *Config) AgentGuestInstallPath() string {
	p := strings.TrimSpace(c.Agent.InstallPath)
	if p != "" && !strings.Contains(strings.ToLower(p), `\program files`) {
		return p
	}
	base := strings.TrimSpace(c.Guest.CopyTargetDir)
	if base == "" {
		base = `C:\Users\Public\Quarantine`
	}
	return filepath.Join(base, "quarantine-agent.exe")
}

// SaveAgentToken writes the bearer token to the configured host token file.
func (c *Config) SaveAgentToken(token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("empty agent token")
	}
	path := strings.TrimSpace(c.Agent.TokenFile)
	if path == "" {
		return fmt.Errorf("agent.tokenFile not configured")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create token dir: %w", err)
	}
	return os.WriteFile(path, []byte(token+"\n"), 0o600)
}

// AgentToken returns bearer token from inline config or token file.
func (c *Config) AgentToken() (string, error) {
	if strings.TrimSpace(c.Agent.Token) != "" {
		return strings.TrimSpace(c.Agent.Token), nil
	}
	if strings.TrimSpace(c.Agent.TokenFile) == "" {
		return "", fmt.Errorf("agent.token or agent.tokenFile required")
	}
	raw, err := os.ReadFile(c.Agent.TokenFile)
	if err != nil {
		return "", fmt.Errorf("read agent token file: %w", err)
	}
	tok := strings.TrimSpace(string(bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})))
	if tok == "" {
		return "", fmt.Errorf("agent token file is empty")
	}
	return tok, nil
}

// AgentHostBinary resolves path to quarantine-agent.exe on the host.
func (c *Config) AgentHostBinary(projectRoot string) string {
	if strings.TrimSpace(c.Agent.HostBinaryPath) != "" {
		return c.Agent.HostBinaryPath
	}
	candidates := []string{
		filepath.Join(projectRoot, "go", "quarantine-agent.exe"),
		filepath.Join(projectRoot, "go", "cmd", "quarantine-agent", "quarantine-agent.exe"),
		filepath.Join(projectRoot, "go", "cmd", "quarantine", "build", "bin", "quarantine-agent.exe"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return candidates[0]
}

// ProjectRoot returns the VM repo root (parent of config file's project).
func ProjectRoot(configPath string) string {
	return filepath.Dir(filepath.Dir(configPath))
}

// DataDir returns vmDataDir.
func (c *Config) DataDir() string {
	return c.VMDataDir
}

// VMFolder returns {vmDataDir}/{vmName}.
func (c *Config) VMFolder() string {
	return filepath.Join(c.DataDir(), c.VMName)
}

// DiskPathResolved returns configured disk or default {vmDataDir}/{vmName}/{vmName}.vdi.
func (c *Config) DiskPathResolved() string {
	if strings.TrimSpace(c.DiskPath) != "" {
		return c.DiskPath
	}
	return filepath.Join(c.DataDir(), c.VMName, c.VMName+".vdi")
}

// ManifestLogDir returns manifest.logDir or default under data dir.
func (c *Config) ManifestLogDir() string {
	if strings.TrimSpace(c.Manifest.LogDir) != "" {
		return c.Manifest.LogDir
	}
	return filepath.Join(c.DataDir(), "logs", "manifests")
}

// VBoxFile returns path to {vmName}.vbox.
func (c *Config) VBoxFile() string {
	return filepath.Join(c.VMFolder(), c.VMName+".vbox")
}

// SafeSnapshotFileName sanitizes snapshot names for sidecar filenames.
func SafeSnapshotFileName(name string) string {
	invalid := []string{`<`, `>`, `:`, `"`, `/`, `\`, `|`, `?`, `*`}
	s := strings.TrimSpace(name)
	for _, ch := range invalid {
		s = strings.ReplaceAll(s, ch, "_")
	}
	return s
}

// SidecarPath returns path for a snapshot sidecar suffix e.g. "-sysmon.json".
func (c *Config) SidecarPath(snapshotName, suffix string) string {
	safe := SafeSnapshotFileName(snapshotName)
	return filepath.Join(c.ManifestLogDir(), safe+suffix)
}

// ManifestPath returns canonical manifest JSON path for a snapshot.
func (c *Config) ManifestPath(snapshotName string) string {
	return c.SidecarPath(snapshotName, ".json")
}

// ResolveSnapshotName maps short names like "hostfile" to "Evidence-hostfile" when present.
func (c *Config) ResolveSnapshotName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return name
	}
	aliases := map[string]string{
		"clean":         c.CleanSnapshot,
		"cleansession":  c.Manifest.SessionBaselineSnapshot,
		"baseline":      c.Manifest.SessionBaselineSnapshot,
	}
	if mapped, ok := aliases[strings.ToLower(name)]; ok {
		name = mapped
	}
	// If manifest sidecar exists for exact name, use it.
	if _, err := os.Stat(c.ManifestPath(name)); err == nil {
		return name
	}
	evidence := "Evidence-" + name
	if _, err := os.Stat(c.ManifestPath(evidence)); err == nil {
		return evidence
	}
	if _, err := os.Stat(c.SidecarPath(name, "-payload-registry.json")); err == nil {
		return name
	}
	evidenceSidecar := c.SidecarPath(evidence, "-payload-registry.json")
	if _, err := os.Stat(evidenceSidecar); err == nil {
		return evidence
	}
	return name
}
