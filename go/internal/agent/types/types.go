package types

import "encoding/json"

const Version = "1.0.20"

// FileMaxBytes is the /v1/files PUT/GET cap (64 MiB).
const FileMaxBytes = 64 << 20

// CaptureRequest is POST /v1/capture body.
type CaptureRequest struct {
	Snapshot        string          `json:"snapshot"`
	Mode            string          `json:"mode"` // baseline | evidence
	Baseline        json.RawMessage `json:"baseline,omitempty"`
	BaselineAt      string          `json:"baselineAt,omitempty"`
	HashMaxMB       int             `json:"hashMaxMb,omitempty"`
	ContentMaxKB    int             `json:"contentMaxKb,omitempty"`
	TotalEmbedMaxMB int             `json:"totalEmbedMaxMb,omitempty"`
	PayloadUser     string          `json:"payloadUser,omitempty"`
}

// CaptureResponse is returned by capture endpoints.
type CaptureResponse struct {
	Snapshot        string          `json:"snapshot"`
	CapturedAt      string          `json:"capturedAt"`
	ComputerName    string          `json:"computerName"`
	Baseline        json.RawMessage `json:"baseline,omitempty"`
	USN             json.RawMessage `json:"usn"`
	Sysmon          json.RawMessage `json:"sysmon"`
	ServiceInstalls json.RawMessage `json:"serviceInstalls"`
	Registry        RegistryBundle  `json:"registry"`
	Hives           *HiveDump       `json:"hives,omitempty"`
	ChangedFiles    json.RawMessage `json:"changedFiles"`
	Warnings        []string        `json:"warnings,omitempty"`
	Stats           CaptureStats    `json:"stats,omitempty"`
}

// HiveDump is a guest-side `reg save` of full hives for host-side indexing.
type HiveDump struct {
	GuestDir string     `json:"guestDir"`
	Files    []HiveFile `json:"files"`
	Warnings []string   `json:"warnings,omitempty"`
}

// HiveFile is one saved hive on the guest.
type HiveFile struct {
	Name      string `json:"name"`
	GuestPath string `json:"guestPath"`
	Prefix    string `json:"prefix"`
}

type CaptureStats struct {
	USNEvents            int `json:"usnEvents"`
	SysmonEvents         int `json:"sysmonEvents"`
	ServiceInstallEvents int `json:"serviceInstallEvents"`
	HKLMEntries          int `json:"hklmEntries"`
	HKCUEntries          int `json:"hkcuEntries"`
	HKUEntries           int `json:"hkuEntries"`
	ChangedFiles         int `json:"changedFiles"`
}

type RegistryBundle struct {
	HKLM     []RegistryEntry `json:"hklm"`
	HKCU     []RegistryEntry `json:"hkcu"`
	HKU      []RegistryEntry `json:"hku,omitempty"` // .DEFAULT / system SIDs
	Warnings []string        `json:"warnings,omitempty"`
	SID      string          `json:"sid,omitempty"`
	UserName string          `json:"userName,omitempty"`
}

type RegistryEntry struct {
	K string `json:"k"`
	N string `json:"n"`
	T string `json:"t"`
	V any    `json:"v"`
}

// HealthResponse is GET /health body.
type HealthResponse struct {
	Version           string `json:"version"`
	UptimeSec         int64  `json:"uptimeSec"`
	ComputerName      string `json:"computerName"`
	SysmonAvailable   bool   `json:"sysmonAvailable"`
	USNAvailable      bool   `json:"usnAvailable"`
	CaptureReady      bool   `json:"captureReady"`
	PayloadSession    bool   `json:"payloadSession"`
	PayloadUser       string `json:"payloadUser,omitempty"`
	PayloadUserLogged string `json:"payloadUserLogged,omitempty"`
}

// ExecRequest is POST /v1/exec body.
type ExecRequest struct {
	Exe       string   `json:"exe"`
	Args      []string `json:"args,omitempty"`
	User      string   `json:"user,omitempty"` // system | guest | payload
	TimeoutMs int      `json:"timeoutMs,omitempty"`
}

// ExecResponse is POST /v1/exec result.
type ExecResponse struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exitCode"`
	Error    string `json:"error,omitempty"`
}

// AgentConfig is persisted on the guest.
type AgentConfig struct {
	Port        int    `json:"port"`
	TokenFile   string `json:"tokenFile"`
	PayloadUser string `json:"payloadUser"`
	LabAdmin    string `json:"labAdmin,omitempty"`
	SysmonLog   string `json:"sysmonLog"`
	SysmonDir   string `json:"sysmonDir,omitempty"`
}
