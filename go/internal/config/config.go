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
	VMName           string          `json:"vmName"`
	GuestOSType      string          `json:"guestOsType"`
	MemoryMB         int             `json:"memoryMb"`
	CPUCount         int             `json:"cpuCount"`
	DiskSizeGB       int             `json:"diskSizeGb"`
	VMDataDir        string          `json:"vmDataDir"`
	DiskPath         string          `json:"diskPath"`
	WindowsISOPath   string          `json:"windowsIsoPath"`
	AutounattendPath string          `json:"autounattendPath"`
	VBoxManagePath   string          `json:"vboxManagePath"`
	Network          NetworkConfig   `json:"network"`
	Isolation        IsolationConfig `json:"isolation"`
	Inbox            InboxConfig     `json:"inbox"`
	Guest            AccountConfig   `json:"guest"`
	Payload          AccountConfig   `json:"payload"`
	Sysmon           SysmonConfig    `json:"sysmon"`
	CleanSnapshot    string          `json:"cleanSnapshotName"`
	Firmware         string          `json:"firmware"`
	Manifest         ManifestConfig  `json:"manifest"`
	Agent            AgentConfig     `json:"agent"`
	UI               UIConfig        `json:"ui"`
}

// UIConfig controls desktop UI behaviour.
type UIConfig struct {
	// WarnPublicIPBeforeLaunch shows host public IP/ISP before Launch (default true).
	WarnPublicIPBeforeLaunch *bool `json:"warnPublicIpBeforeLaunch"`
	// HomeISPPatterns are case-insensitive substrings of the public ISP/org that
	// count as home (non-VPN) egress. Shown in red in the launch prompt.
	// Omitted/null defaults to ["Community Fibre"]. An empty list means nothing is home.
	HomeISPPatterns []string `json:"homeIspPatterns"`
}

var defaultHomeISPPatterns = []string{"Community Fibre"}

// WarnPublicIPBeforeLaunchEnabled is true unless explicitly disabled in config.
func (c *Config) WarnPublicIPBeforeLaunchEnabled() bool {
	if c == nil || c.UI.WarnPublicIPBeforeLaunch == nil {
		return true
	}
	return *c.UI.WarnPublicIPBeforeLaunch
}

// HomeISPPatterns returns configured home-ISP match strings, or the default.
// A non-nil empty slice means "no home ISPs" (everything treated as non-home).
func (c *Config) HomeISPPatterns() []string {
	if c == nil || c.UI.HomeISPPatterns == nil {
		out := make([]string, len(defaultHomeISPPatterns))
		copy(out, defaultHomeISPPatterns)
		return out
	}
	return c.UI.HomeISPPatterns
}

// IsHomeISP reports whether any ISP/org string matches a configured home pattern.
func (c *Config) IsHomeISP(parts ...string) bool {
	patterns := c.HomeISPPatterns()
	if len(patterns) == 0 {
		return false
	}
	var b strings.Builder
	for _, p := range parts {
		b.WriteString(strings.ToLower(strings.TrimSpace(p)))
		b.WriteByte(' ')
	}
	hay := b.String()
	for _, pat := range patterns {
		pat = strings.ToLower(strings.TrimSpace(pat))
		if pat == "" {
			continue
		}
		if strings.Contains(hay, pat) {
			return true
		}
	}
	return false
}

type AgentConfig struct {
	Enabled        bool   `json:"enabled"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Token          string `json:"token"`
	TokenFile      string `json:"tokenFile"`
	NatRuleName    string `json:"natRuleName"`
	InstallPath    string `json:"installPath"`
	HostBinaryPath string `json:"hostBinaryPath"`
}

type NetworkConfig struct {
	Mode            string        `json:"mode"`
	HostOnlyAdapter string        `json:"hostOnlyAdapter"`
	IntnetName      string        `json:"intnetName"`
	GuestGateway    string        `json:"guestGateway"`
	GuestDNS        string        `json:"guestDns"`
	Proxy           ProxyConfig   `json:"proxy"`
	Capture         CaptureConfig `json:"capture"`
	Gateway         GatewayConfig `json:"gateway"`
}

// GatewayConfig describes the Linux quarantine gateway VM.
type GatewayConfig struct {
	Enabled     bool   `json:"enabled"`
	VMName      string `json:"vmName"`
	LANCidr     string `json:"lanCidr"`
	LANGateway  string `json:"lanGateway"`
	GuestIP     string `json:"guestIp"`
	IntnetName  string `json:"intnetName"`
	Uplink      string `json:"uplink"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	SSHHostPort int    `json:"sshHostPort"`
	MemoryMB    int    `json:"memoryMb"`
	CPUCount    int    `json:"cpuCount"`
	DiskSizeGB  int    `json:"diskSizeGb"`
	// TrafficMode is "permissive" (allowlisted internet + MITM) or "fakenet" (LAN sinkhole).
	TrafficMode string `json:"trafficMode"`
	// Permissive is the WAN allowlist used only in permissive mode.
	Permissive PermissivePolicy `json:"permissive"`
}

// PermissivePolicy is the LAN→WAN allowlist for real-internet mode.
// TCP 80/443 are always MITM'd (never forwarded raw). Extra ports go to WAN.
type PermissivePolicy struct {
	TCPPorts          []int `json:"tcpPorts"`
	UDPPorts          []int `json:"udpPorts"`
	ForceDNSToGateway *bool `json:"forceDnsToGateway"`
	AllowICMP         *bool `json:"allowIcmp"`
}

// DefaultPermissivePolicy is standard web + DNS via the gateway + ICMP ping.
func DefaultPermissivePolicy() PermissivePolicy {
	dns := true
	icmp := true
	return PermissivePolicy{
		TCPPorts:          []int{80, 443},
		UDPPorts:          []int{},
		ForceDNSToGateway: &dns,
		AllowICMP:         &icmp,
	}
}

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

func (p PermissivePolicy) ForceDNS() bool { return boolOr(p.ForceDNSToGateway, true) }
func (p PermissivePolicy) ICMP() bool     { return boolOr(p.AllowICMP, true) }

func (p PermissivePolicy) WithDefaults() PermissivePolicy {
	d := DefaultPermissivePolicy()
	if p.TCPPorts == nil {
		p.TCPPorts = d.TCPPorts
	}
	if p.UDPPorts == nil {
		p.UDPPorts = d.UDPPorts
	}
	if p.ForceDNSToGateway == nil {
		p.ForceDNSToGateway = d.ForceDNSToGateway
	}
	if p.AllowICMP == nil {
		p.AllowICMP = d.AllowICMP
	}
	return p
}

// WithDefaults fills gateway fields from intnet name when empty.
func (g GatewayConfig) WithDefaults(intnetFallback string) GatewayConfig {
	if g.VMName == "" {
		g.VMName = "Quarantine-Gateway"
	}
	if g.LANCidr == "" {
		g.LANCidr = "10.66.0.0/24"
	}
	if g.LANGateway == "" {
		g.LANGateway = "10.66.0.1"
	}
	if g.GuestIP == "" {
		g.GuestIP = "10.66.0.15"
	}
	if g.IntnetName == "" {
		g.IntnetName = intnetFallback
	}
	if g.IntnetName == "" {
		g.IntnetName = "quarantine-net"
	}
	if g.Uplink == "" {
		g.Uplink = "nat"
	}
	if g.Username == "" {
		g.Username = "quarantine"
	}
	if g.Password == "" {
		g.Password = "quarantine"
	}
	if g.SSHHostPort <= 0 {
		g.SSHHostPort = 2222
	}
	if g.MemoryMB <= 0 {
		g.MemoryMB = 1024
	}
	if g.CPUCount <= 0 {
		g.CPUCount = 1
	}
	if g.DiskSizeGB <= 0 {
		g.DiskSizeGB = 16
	}
	tm, _ := NormalizeTrafficMode(g.TrafficMode)
	if tm == "" {
		tm = "fakenet"
	}
	g.TrafficMode = tm
	g.Permissive = g.Permissive.WithDefaults()
	return g
}

// NormalizeTrafficMode maps CLI/UI aliases to permissive or fakenet.
// Empty defaults to FakeNet (contained).
func NormalizeTrafficMode(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "fakenet", "sinkhole":
		return "fakenet", nil
	case "permissive", "mitm", "internet":
		return "permissive", nil
	default:
		return "", fmt.Errorf("unknown traffic mode %q (use permissive or fakenet)", s)
	}
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
	DisableClipboard     bool          `json:"disableClipboard"`
	ClipboardMode        string        `json:"clipboardMode"`
	DisableDragDrop      bool          `json:"disableDragDrop"`
	DisableUSB           bool          `json:"disableUsb"`
	DisableAudio         bool          `json:"disableAudio"`
	DisableSharedFolders bool          `json:"disableSharedFolders"`
	Stealth              StealthConfig `json:"stealth"`
}

// StealthConfig blunts common VirtualBox guest fingerprints without removing Guest Additions.
// Graphics (VBoxSVGA) and VBox* drivers remain by design — required for guestcontrol/clipboard/resize.
type StealthConfig struct {
	Enabled          *bool             `json:"enabled"` // nil/absent = on when stealth object present with defaults from Apply
	CPUProfile       string            `json:"cpuProfile"`
	ParavirtProvider string            `json:"paravirtProvider"` // empty = leave VirtualBox default (Hyper-V for Win11)
	MacAddress       string            `json:"macAddress"`       // 12 hex or AA:BB:...; "auto" = generate Dell-OUI once
	MacOUI           string            `json:"macOui"`           // used when macAddress is empty/auto (default F8B156)
	DMI              map[string]string `json:"dmi"`
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
	if cfg.Manifest.RegistryEngine == "" || strings.EqualFold(cfg.Manifest.RegistryEngine, "cli") ||
		strings.EqualFold(cfg.Manifest.RegistryEngine, "payload") ||
		strings.EqualFold(cfg.Manifest.RegistryEngine, "legacy") ||
		strings.EqualFold(cfg.Manifest.RegistryEngine, "powershell") {
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
	mode := strings.ToLower(strings.TrimSpace(cfg.Network.Mode))
	if mode == "" || mode == "host-nat" || mode == "quarantine" {
		cfg.Network.Mode = "gateway"
		cfg.Network.Gateway.Enabled = true
	}
	if strings.TrimSpace(cfg.Network.Capture.Mode) == "" ||
		strings.EqualFold(cfg.Network.Capture.Mode, "guest-nic") ||
		strings.EqualFold(cfg.Network.Capture.Mode, "vbox-nictrace") {
		if cfg.Network.Gateway.Enabled || strings.EqualFold(cfg.Network.Mode, "gateway") {
			cfg.Network.Capture.Mode = "gateway"
		}
	}
	if tm, err := NormalizeTrafficMode(cfg.Network.Gateway.TrafficMode); err == nil {
		cfg.Network.Gateway.TrafficMode = tm
	} else {
		cfg.Network.Gateway.TrafficMode = "fakenet"
	}
	cfg.Network.Gateway.Permissive = cfg.Network.Gateway.Permissive.WithDefaults()
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

// IsGatewayMode reports whether the Linux gateway path is in use.
// Host-NAT mitm is retired; gateway.enabled or mode=gateway both count.
func (c *Config) IsGatewayMode() bool {
	if c == nil {
		return true
	}
	if c.Network.Gateway.Enabled {
		return true
	}
	mode := strings.ToLower(strings.TrimSpace(c.Network.Mode))
	return mode == "" || mode == "gateway"
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
		"clean":        c.CleanSnapshot,
		"cleansession": c.Manifest.SessionBaselineSnapshot,
		"baseline":     c.Manifest.SessionBaselineSnapshot,
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
