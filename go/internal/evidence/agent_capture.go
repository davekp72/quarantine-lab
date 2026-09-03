package evidence

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quarantine-lab/quarantine/internal/agent/types"
	"github.com/quarantine-lab/quarantine/internal/agentclient"
	"github.com/quarantine-lab/quarantine/internal/guest"
)

func (s *Service) agentClient() (*agentclient.Client, error) {
	if err := s.EnsureHostAgentToken(); err != nil {
		return nil, err
	}
	return agentclient.New(s.Cfg)
}

const guestAgentTokenPath = `C:\Users\Public\Quarantine\agent\agent-token.txt`
const guestAgentInstallScript = `C:\Users\Public\Quarantine\Install-QuarantineAgent.ps1`
const guestAgentInstallConfig = `C:\Users\Public\Quarantine\agent\agent-install.json`

// EnsureHostAgentToken loads the host token file or syncs it from the guest agent install.
func (s *Service) EnsureHostAgentToken() error {
	if _, err := s.Cfg.AgentToken(); err == nil {
		return nil
	}
	return s.SyncAgentTokenFromGuest()
}

// SyncAgentTokenFromGuest copies agent-token.txt from the guest to the host tokenFile path.
func (s *Service) SyncAgentTokenFromGuest() error {
	if strings.TrimSpace(s.Cfg.Agent.TokenFile) == "" && strings.TrimSpace(s.Cfg.Agent.Token) == "" {
		return fmt.Errorf("configure agent.tokenFile or agent.token in quarantine-vm.json")
	}
	creds := s.Guest.GuestCreds()
	tmp := filepath.Join(os.TempDir(), "quarantine-agent-token-sync.txt")
	if err := s.copyFromGuest(guestAgentTokenPath, tmp, creds); err != nil {
		return fmt.Errorf("sync token from guest (%s): %w — install agent in VM first", guestAgentTokenPath, err)
	}
	raw, err := os.ReadFile(tmp)
	_ = os.Remove(tmp)
	if err != nil {
		return err
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" {
		return fmt.Errorf("guest agent token file is empty")
	}
	if err := s.Cfg.SaveAgentToken(tok); err != nil {
		return err
	}
	return nil
}

// SaveHostAgentToken writes a token provided by the user to the host token file.
func (s *Service) SaveHostAgentToken(token string) error {
	return s.Cfg.SaveAgentToken(token)
}

// MarkLiveSnapshot captures evidence via the VM quarantine-agent HTTP API.
func (s *Service) MarkLiveSnapshot(snapshotName string) (string, error) {
	if !s.Cfg.Agent.Enabled {
		return s.markLiveSnapshotLegacy(snapshotName)
	}

	client, err := s.agentClient()
	if err != nil {
		return "", err
	}
	ctx := context.Background()

	health, err := client.Health(ctx)
	if err != nil {
		host := s.Cfg.Agent.Host
		if host == "" {
			host = "127.0.0.1"
		}
		port := s.Cfg.Agent.Port
		if port <= 0 {
			port = 9443
		}
		return "", fmt.Errorf("agent not reachable at %s:%d (%w) — in guest: sc query QuarantineLabAgent, netsh advfirewall show rule name=\"Quarantine Lab Agent\"",
			host, port, err)
	}
	if !health.PayloadSession && strings.TrimSpace(s.Cfg.Payload.Username) != "" {
		// HKCU may be missing; capture still proceeds with warning in response.
	}

	snap := s.Cfg.ResolveSnapshotName(snapshotName)
	engine := strings.ToLower(strings.TrimSpace(s.Cfg.Manifest.RegistryEngine))
	if engine == "regshot" {
		return "", fmt.Errorf("regshot registry engine is not supported in the Go UI yet")
	}

	isEvidence := strings.HasPrefix(strings.ToLower(snap), "evidence-")
	baselineName := strings.TrimSpace(s.Cfg.Manifest.SessionBaselineSnapshot)

	req := types.CaptureRequest{
		Snapshot:     snap,
		PayloadUser:  s.Cfg.Payload.Username,
		HashMaxMB:    s.Cfg.Manifest.HashMaxMB,
		ContentMaxKB: s.Cfg.Manifest.ContentMaxKB,
	}

	if isEvidence && baselineName != "" {
		req.Mode = "evidence"
		baselinePath := s.Cfg.SidecarPath(s.Cfg.ResolveSnapshotName(baselineName), "-baseline.json")
		raw, err := os.ReadFile(baselinePath)
		if err != nil {
			return "", fmt.Errorf("USN baseline missing for %q (%s)", baselineName, baselinePath)
		}
		req.Baseline = json.RawMessage(raw)
		var b map[string]any
		if json.Unmarshal(raw, &b) == nil {
			req.BaselineAt, _ = b["recordedAt"].(string)
		}
	} else {
		req.Mode = "baseline"
	}

	resp, err := client.Capture(ctx, req)
	if err != nil {
		return "", err
	}

	if err := s.writeSidecarsFromCapture(snap, resp); err != nil {
		return "", err
	}
	return s.PublishFromSidecars(snap)
}

func (s *Service) writeSidecarsFromCapture(snapshotName string, resp *types.CaptureResponse) error {
	writeRaw := func(suffix string, raw json.RawMessage) error {
		if len(raw) == 0 {
			return nil
		}
		path := s.Cfg.SidecarPath(snapshotName, suffix)
		return os.WriteFile(path, prettyJSON(raw), 0o644)
	}
	writeObj := func(suffix string, v any) error {
		raw, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(s.Cfg.SidecarPath(snapshotName, suffix), raw, 0o644)
	}

	if len(resp.Baseline) > 0 {
		if err := writeRaw("-baseline.json", resp.Baseline); err != nil {
			return fmt.Errorf("baseline sidecar: %w", err)
		}
	}
	if err := writeRaw("-usn-delta.json", resp.USN); err != nil {
		return fmt.Errorf("usn sidecar: %w", err)
	}
	if err := writeRaw("-sysmon.json", resp.Sysmon); err != nil {
		return fmt.Errorf("sysmon sidecar: %w", err)
	}
	if err := writeRaw("-service-installs.json", resp.ServiceInstalls); err != nil {
		return fmt.Errorf("service-install sidecar: %w", err)
	}
	if err := writeRaw("-changed-files.json", resp.ChangedFiles); err != nil {
		return fmt.Errorf("changed-files sidecar: %w", err)
	}

	payloadExport := map[string]any{
		"engine":     "cli",
		"capturedAt": resp.CapturedAt,
		"snapshot":   snapshotName,
		"userName":   resp.Registry.UserName,
		"sid":        resp.Registry.SID,
		"entryCount": len(resp.Registry.HKCU),
		"registry":   resp.Registry.HKCU,
	}
	if len(resp.Registry.Warnings) > 0 {
		payloadExport["warnings"] = resp.Registry.Warnings
	}
	if err := writeObj("-payload-registry.json", payloadExport); err != nil {
		return fmt.Errorf("payload registry sidecar: %w", err)
	}

	machine := append(append([]types.RegistryEntry{}, resp.Registry.HKLM...), resp.Registry.HKU...)
	hklmExport := map[string]any{
		"engine":     "cli",
		"scope":      "hklm+hku",
		"capturedAt": resp.CapturedAt,
		"snapshot":   snapshotName,
		"entryCount": len(machine),
		"hklmCount":  len(resp.Registry.HKLM),
		"hkuCount":   len(resp.Registry.HKU),
		"registry":   machine,
	}
	if err := writeObj("-hklm-registry.json", hklmExport); err != nil {
		return fmt.Errorf("hklm registry sidecar: %w", err)
	}
	if resp.Hives != nil && len(resp.Hives.Files) > 0 {
		if err := s.pullHiveDump(snapshotName, resp.Hives); err != nil {
			return fmt.Errorf("hive dump pull: %w", err)
		}
	}
	return nil
}

// pullHiveDump copies guest `reg save` hive files to the host manifests folder.
func (s *Service) pullHiveDump(snapshotName string, dump *types.HiveDump) error {
	hostDir := s.RegistryHivesDir(snapshotName)
	_ = os.RemoveAll(hostDir)
	if err := os.MkdirAll(hostDir, 0o755); err != nil {
		return err
	}
	creds := s.Guest.GuestCreds()
	manifest := map[string]any{
		"guestDir": dump.GuestDir,
		"files":    []map[string]any{},
		"warnings": dump.Warnings,
	}
	var files []map[string]any
	for _, f := range dump.Files {
		hostPath := filepath.Join(hostDir, f.Name)
		if err := s.copyFromGuest(f.GuestPath, hostPath, creds); err != nil {
			return fmt.Errorf("copy %s: %w", f.GuestPath, err)
		}
		files = append(files, map[string]any{
			"name":      f.Name,
			"hostPath":  hostPath,
			"guestPath": f.GuestPath,
			"prefix":    f.Prefix,
		})
	}
	manifest["files"] = files
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(hostDir, "manifest.json"), raw, 0o644)
}

func prettyJSON(raw json.RawMessage) []byte {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return raw
	}
	return out
}

// DeployAgent copies the agent binary, install script, and config into the guest.
// Service install is performed manually via Install-QuarantineAgent.ps1 (elevated guest PowerShell).
func (s *Service) DeployAgent(token string) (string, error) {
	if !s.Cfg.Agent.Enabled {
		return "", fmt.Errorf("agent.enabled is false in config")
	}
	hostBin := s.Cfg.AgentHostBinary(s.ProjectRoot)
	if _, err := os.Stat(hostBin); err != nil {
		return "", fmt.Errorf("agent binary not found at %s (build with: go build -o quarantine-agent.exe ./cmd/quarantine-agent)", hostBin)
	}
	hostScript := filepath.Join(s.ProjectRoot, "manifest", "Install-QuarantineAgent.ps1")
	if _, err := os.Stat(hostScript); err != nil {
		return "", fmt.Errorf("agent install script not found at %s", hostScript)
	}

	guestDir := filepath.Dir(s.Cfg.AgentGuestInstallPath())
	creds := s.Guest.GuestCreds()

	if token == "" {
		if t, err := s.Cfg.AgentToken(); err == nil {
			token = t
		} else {
			token = randomAgentToken()
		}
	}
	if strings.TrimSpace(s.Cfg.Agent.TokenFile) != "" {
		_ = s.Cfg.SaveAgentToken(token)
	}

	_ = s.VBox.GuestControlMkdir(s.Cfg.VMName, creds.Username, creds.Password, guestDir, s.captureTimeout())
	agentConfigDir := filepath.Dir(guestAgentInstallConfig)
	_ = s.VBox.GuestControlMkdir(s.Cfg.VMName, creds.Username, creds.Password, agentConfigDir, s.captureTimeout())

	guestStaging, err := s.copyAgentBinary(hostBin, guestDir, creds)
	if err != nil {
		return "", err
	}
	if err := s.VBox.GuestControlCopyTo(
		s.Cfg.VMName, creds.Username, creds.Password,
		hostScript, guestAgentInstallScript, s.captureTimeout(),
	); err != nil {
		return "", fmt.Errorf("copy install script to guest: %w", err)
	}

	installCfg := map[string]any{
		"version":     types.Version,
		"binary":      guestStaging,
		"port":        s.Cfg.Agent.Port,
		"payloadUser": s.Cfg.Payload.Username,
		"token":       token,
	}
	if s.Cfg.Sysmon.EventLog != "" {
		installCfg["sysmonLog"] = s.Cfg.Sysmon.EventLog
	}
	cfgRaw, err := json.MarshalIndent(installCfg, "", "  ")
	if err != nil {
		return "", err
	}
	tmpCfg := filepath.Join(os.TempDir(), "quarantine-agent-install.json")
	if err := os.WriteFile(tmpCfg, cfgRaw, 0o644); err != nil {
		return "", err
	}
	defer os.Remove(tmpCfg)
	if err := s.VBox.GuestControlCopyTo(
		s.Cfg.VMName, creds.Username, creds.Password,
		tmpCfg, guestAgentInstallConfig, s.captureTimeout(),
	); err != nil {
		return "", fmt.Errorf("copy agent install config to guest: %w", err)
	}

	return token, nil
}

func (s *Service) copyAgentBinary(hostBin, guestDir string, creds guest.Credentials) (string, error) {
	if err := verifyAgentBinaryVersion(hostBin, types.Version); err != nil {
		return "", err
	}
	// Stop the running service so the canonical path is not sharing-locked on an old binary.
	s.stopGuestAgentService(creds)

	versionTag := strings.ReplaceAll(types.Version, ".", "-")
	stamp := time.Now().Unix()
	dests := []string{
		// Unique first so a locked stale vN.exe never becomes the only successful copy.
		filepath.Join(guestDir, fmt.Sprintf("quarantine-agent-v%s-deploy-%d.exe", versionTag, stamp)),
		filepath.Join(guestDir, fmt.Sprintf("quarantine-agent-v%s-new.exe", versionTag)),
		filepath.Join(guestDir, fmt.Sprintf("quarantine-agent-v%s.exe", versionTag)),
	}
	var lastErr error
	var copied string
	for _, dest := range dests {
		err := s.VBox.GuestControlCopyTo(
			s.Cfg.VMName, creds.Username, creds.Password,
			hostBin, dest, s.captureTimeout(),
		)
		if err == nil {
			copied = dest
			break
		}
		lastErr = err
		if !isGuestFileSharingViolation(err) {
			return "", fmt.Errorf("copy agent binary to %s: %w", dest, err)
		}
	}
	if copied == "" {
		return "", fmt.Errorf("copy agent binary: all destinations locked (stop QuarantineLabAgent service in guest or reboot VM): %w", lastErr)
	}
	return copied, nil
}

func (s *Service) stopGuestAgentService(creds guest.Credentials) {
	timeout := s.captureTimeout()
	_, _ = s.VBox.GuestControlRun(
		s.Cfg.VMName, creds.Username, creds.Password,
		`C:\Windows\System32\sc.exe`,
		[]string{"stop", "QuarantineLabAgent"},
		timeout,
	)
	time.Sleep(2 * time.Second)
	_, _ = s.VBox.GuestControlRun(
		s.Cfg.VMName, creds.Username, creds.Password,
		`C:\Windows\System32\cmd.exe`,
		[]string{"/c", "taskkill /F /IM quarantine-agent.exe /IM quarantine-agent-v1-0-11.exe /IM quarantine-agent-v1-0-10.exe /IM quarantine-agent-v1-0-9.exe 2>nul"},
		timeout,
	)
	time.Sleep(1 * time.Second)
}

func verifyAgentBinaryVersion(hostBin, want string) error {
	raw, err := os.ReadFile(hostBin)
	if err != nil {
		return fmt.Errorf("read agent binary: %w", err)
	}
	if !bytes.Contains(raw, []byte(want)) {
		return fmt.Errorf("host agent binary %s does not embed version %q — rebuild with: go build -o go/quarantine-agent.exe ./cmd/quarantine-agent", hostBin, want)
	}
	return nil
}

func isGuestFileSharingViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "sharing violation") || strings.Contains(msg, "could not be created or replaced")
}

// AgentInstallInstructions returns the elevated guest install command after DeployAgent.
func AgentInstallInstructions() string {
	return "Set-ExecutionPolicy -Scope Process Bypass; & '" + guestAgentInstallScript + "'"
}

// AgentHealth queries the guest agent /health endpoint.
func (s *Service) AgentHealth(ctx context.Context) (*types.HealthResponse, error) {
	client, err := s.agentClient()
	if err != nil {
		return nil, err
	}
	h, err := client.Health(ctx)
	if err != nil && strings.Contains(err.Error(), "401") {
		if syncErr := s.SyncAgentTokenFromGuest(); syncErr == nil {
			client, cErr := s.agentClient()
			if cErr == nil {
				return client.Health(ctx)
			}
		}
		return nil, fmt.Errorf("%w — run: quarantine agent sync-token", err)
	}
	return h, err
}

func randomAgentToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

