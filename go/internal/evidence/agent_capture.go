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

	"github.com/quarantine-lab/quarantine/internal/agent/guestpaths"
	"github.com/quarantine-lab/quarantine/internal/agent/types"
	"github.com/quarantine-lab/quarantine/internal/agentclient"
	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/guest"
)

func (s *Service) agentClient() (*agentclient.Client, error) {
	if err := s.EnsureHostAgentToken(); err != nil {
		return nil, err
	}
	return agentclient.New(s.Cfg)
}

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
	tmp := filepath.Join(os.TempDir(), "quarantine-agent-token-sync.txt")
	var errs []string
	if client, cErr := agentclient.New(s.Cfg); cErr == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		for _, guestPath := range []string{guestpaths.TokenPath(), guestpaths.StagingTokenPath(), guestpaths.SyncExportPath()} {
			if err := client.GetFile(ctx, guestPath, tmp); err != nil {
				errs = append(errs, guestPath+": "+shortGuestErr(err))
				continue
			}
			if err := s.saveSyncedAgentToken(tmp); err != nil {
				errs = append(errs, guestPath+": "+err.Error())
				continue
			}
			return nil
		}
	} else {
		errs = append(errs, cErr.Error())
	}
	if !s.Cfg.UseGuestAdditions() {
		return fmt.Errorf("sync token via agent failed (%s). %s", strings.Join(errs, "; "), config.AgentUnreachableHint(nil))
	}
	creds := s.Guest.GuestCreds()
	for _, guestPath := range guestpaths.TokenCopyCandidates() {
		if err := s.copyFromGuest(guestPath, tmp, creds); err != nil {
			errs = append(errs, guestPath+": "+shortGuestErr(err))
			continue
		}
		if err := s.saveSyncedAgentToken(tmp); err != nil {
			errs = append(errs, guestPath+": "+err.Error())
			continue
		}
		return nil
	}
	if err := s.syncAgentTokenElevated(tmp, creds); err != nil {
		errs = append(errs, "elevated export: "+shortGuestErr(err))
		return fmt.Errorf("sync token from guest failed (%s). Guest Additions cannot read the ACL-locked token, and schtasks elevation is denied from an unelevated session.\nIn elevated guest PowerShell, either re-run Install-QuarantineAgent.ps1 or paste the Bearer line:\n  quarantine agent set-token --token <token>", strings.Join(errs, "; "))
	}
	return nil
}

func shortGuestErr(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	for _, prefix := range []string{"VBoxManage.exe: error: ", "ERROR: "} {
		if i := strings.LastIndex(msg, prefix); i >= 0 {
			line := strings.TrimSpace(msg[i+len(prefix):])
			if j := strings.IndexAny(line, "\r\n"); j > 0 {
				line = line[:j]
			}
			return line
		}
	}
	if i := strings.Index(msg, "exit status"); i >= 0 {
		rest := strings.TrimSpace(msg[i:])
		if j := strings.Index(rest, ":"); j > 0 && j < 40 {
			return strings.TrimSpace(rest)
		}
	}
	if len(msg) > 180 {
		return msg[:180] + "…"
	}
	return msg
}

func (s *Service) saveSyncedAgentToken(tmp string) error {
	raw, err := os.ReadFile(tmp)
	_ = os.Remove(tmp)
	if err != nil {
		return err
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" {
		return fmt.Errorf("guest agent token file is empty")
	}
	return s.Cfg.SaveAgentToken(tok)
}

func (s *Service) deleteGuestFile(guestPath string, creds guest.Credentials) {
	_ = s.Guest.Remove(guestPath)
}

func (s *Service) syncAgentTokenElevated(hostTmp string, creds guest.Credentials) error {
	guestDir := s.guestDir()
	exportHost := filepath.Join(s.ProjectRoot, "guest", "Export-QuarantineAgentToken.ps1")
	elevHost := filepath.Join(s.ProjectRoot, "guest", "Invoke-QuarantineGuestElevated.ps1")
	if err := s.deployToGuest(exportHost, guestDir, creds); err != nil {
		return err
	}
	if err := s.deployToGuest(elevHost, guestDir, creds); err != nil {
		return err
	}

	outGuest := guestpaths.SyncExportPath()
	s.deleteGuestFile(outGuest, creds)

	credHost := filepath.Join(os.TempDir(), "qv-token-sync-cred.json")
	credRaw, err := json.Marshal(map[string]string{
		"user":     creds.Username,
		"password": creds.Password,
	})
	if err != nil {
		return err
	}
	if err := os.WriteFile(credHost, credRaw, 0o600); err != nil {
		return err
	}
	defer os.Remove(credHost)
	credGuest := filepath.Join(guestDir, "qv-token-sync-cred.json")
	if err := s.Guest.CopyToDest(credHost, credGuest); err != nil {
		return fmt.Errorf("copy elevated creds: %w", err)
	}

	elevGuest := filepath.Join(guestDir, "Invoke-QuarantineGuestElevated.ps1")
	exportGuest := filepath.Join(guestDir, "Export-QuarantineAgentToken.ps1")
	out, err := s.Guest.RunPowerShell(elevGuest, []string{
		"-ScriptPath", exportGuest,
		"-OutFile", outGuest,
		"-CredentialFile", credGuest,
		"-TimeoutSeconds", "90",
	}, creds)
	if err != nil {
		s.deleteGuestFile(outGuest, creds)
		s.deleteGuestFile(credGuest, creds)
		msg := strings.TrimSpace(out)
		if msg == "" {
			return err
		}
		return fmt.Errorf("%w (%s)", err, msg)
	}
	defer s.deleteGuestFile(outGuest, creds)
	if err := s.copyFromGuest(outGuest, hostTmp, creds); err != nil {
		return err
	}
	return s.saveSyncedAgentToken(hostTmp)
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

	isEvidence := strings.HasPrefix(strings.ToLower(snap), "evidence-")
	baselineName := strings.TrimSpace(s.Cfg.Manifest.SessionBaselineSnapshot)

	req := types.CaptureRequest{
		Snapshot:        snap,
		PayloadUser:     s.Cfg.Payload.Username,
		HashMaxMB:       s.Cfg.HashMaxMBResolved(),
		ContentMaxKB:    s.Cfg.ContentMaxKBResolved(),
		TotalEmbedMaxMB: s.Cfg.TotalEmbedMaxMBResolved(),
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

	payloadWarnings := []string{"Registry compare uses hive-index dumps; curated walks omitted"}
	payloadWarnings = append(payloadWarnings, resp.Registry.Warnings...)
	payloadExport := map[string]any{
		"engine":     "hive",
		"capturedAt": resp.CapturedAt,
		"snapshot":   snapshotName,
		"userName":   resp.Registry.UserName,
		"sid":        resp.Registry.SID,
		"entryCount": 0,
		"registry":   []any{},
		"warnings":   payloadWarnings,
	}
	if err := writeObj("-payload-registry.json", payloadExport); err != nil {
		return fmt.Errorf("payload registry sidecar: %w", err)
	}

	hklmExport := map[string]any{
		"engine":     "hive",
		"scope":      "hklm+hku",
		"capturedAt": resp.CapturedAt,
		"snapshot":   snapshotName,
		"entryCount": 0,
		"hklmCount":  0,
		"hkuCount":   0,
		"registry":   []any{},
	}
	if err := writeObj("-hklm-registry.json", hklmExport); err != nil {
		return fmt.Errorf("hklm registry sidecar: %w", err)
	}
	if resp.Hives == nil || len(resp.Hives.Files) == 0 {
		return fmt.Errorf("hive dump missing from agent capture — registry requires reg save dumps")
	}
	if err := s.pullHiveDump(snapshotName, resp.Hives); err != nil {
		return fmt.Errorf("hive dump pull: %w", err)
	}
	return nil
}

// pullHiveDump copies guest `reg save` hive files to the host manifests folder,
// then deletes the guest staging directory (SYSTEM agent HTTP, with guestcontrol fallback).
func (s *Service) pullHiveDump(snapshotName string, dump *types.HiveDump) error {
	hostDir := s.RegistryHivesDir(snapshotName)
	_ = os.RemoveAll(hostDir)
	if err := os.MkdirAll(hostDir, 0o755); err != nil {
		return err
	}
	creds := s.Guest.GuestCreds()
	client, clientErr := s.agentClient()
	ctx, cancel := context.WithTimeout(context.Background(), s.captureTimeout())
	defer cancel()
	manifest := map[string]any{
		"guestDir": dump.GuestDir,
		"files":    []map[string]any{},
		"warnings": dump.Warnings,
	}
	var files []map[string]any
	for _, f := range dump.Files {
		hostPath := filepath.Join(hostDir, f.Name)
		if err := s.pullHiveFile(ctx, client, clientErr, f.GuestPath, hostPath, creds); err != nil {
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
	if err := os.WriteFile(filepath.Join(hostDir, "manifest.json"), raw, 0o644); err != nil {
		return err
	}
	s.deleteGuestHiveDir(ctx, client, clientErr, dump.GuestDir, creds)
	return nil
}

func (s *Service) pullHiveFile(ctx context.Context, client *agentclient.Client, clientErr error, guestPath, hostPath string, creds guest.Credentials) error {
	if clientErr == nil && guestpaths.IsHivePath(guestPath) {
		if err := client.DownloadHive(ctx, guestPath, hostPath); err == nil {
			return nil
		}
	}
	return s.copyFromGuest(guestPath, hostPath, creds)
}

func (s *Service) deleteGuestHiveDir(ctx context.Context, client *agentclient.Client, clientErr error, guestDir string, creds guest.Credentials) {
	if !guestpaths.ShouldDeleteHiveDir(guestDir) {
		return
	}
	if clientErr == nil && guestpaths.IsHivePath(guestDir) {
		if err := client.DeleteHiveDir(ctx, guestDir); err == nil {
			return
		}
	}
	_ = s.Guest.Remove(guestDir)
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

	_ = s.Guest.Transport().Mkdir(context.Background(), guestDir)

	guestStaging, err := s.copyAgentBinary(hostBin, guestDir, creds)
	if err != nil {
		return "", err
	}
	// Prefer agent-staging: Public\Install-QuarantineAgent.ps1 is often ACL/read-only
	// after FirstLogon, and the running agent cannot overwrite it.
	if err := s.Guest.CopyToDest(hostScript, guestpaths.StagingInstallScript()); err != nil {
		return "", fmt.Errorf("copy install script to guest staging: %w", err)
	}
	hostUpgrade := filepath.Join(s.ProjectRoot, "manifest", "Upgrade-QuarantineAgent.ps1")
	if _, err := os.Stat(hostUpgrade); err == nil {
		if err := s.Guest.CopyToDest(hostUpgrade, guestpaths.StagingUpgradeScript()); err != nil {
			return "", fmt.Errorf("copy upgrade script to guest staging: %w", err)
		}
	}

	if err := s.stageGuestToken(token, creds); err != nil {
		return "", err
	}

	installCfg := map[string]any{
		"version":     types.Version,
		"binary":      guestStaging,
		"port":        s.Cfg.Agent.Port,
		"payloadUser": s.Cfg.Payload.Username,
		"labAdmin":    s.Cfg.Guest.Username,
		"installExe":  guestpaths.InstallExe(),
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
	if err := s.Guest.CopyToDest(tmpCfg, guestpaths.StagingInstallConfig()); err != nil {
		return "", fmt.Errorf("copy agent install config to guest staging: %w", err)
	}

	return token, nil
}

func (s *Service) stageGuestToken(token string, creds guest.Credentials) error {
	tmpTok := filepath.Join(os.TempDir(), "quarantine-agent-token-stage.txt")
	if err := os.WriteFile(tmpTok, []byte(strings.TrimSpace(token)+"\n"), 0o600); err != nil {
		return err
	}
	defer os.Remove(tmpTok)
	// Public staging is guestcontrol-writable. ProgramData is created/locked by the elevated installer.
	if err := s.Guest.CopyToDest(tmpTok, guestpaths.StagingTokenPath()); err != nil {
		return fmt.Errorf("stage agent token to guest: %w", err)
	}
	if s.Cfg.UseGuestAdditions() {
		_ = s.Guest.CopyToDest(tmpTok, guestpaths.TokenPath())
	}
	return nil
}

func (s *Service) copyAgentBinary(hostBin, guestDir string, creds guest.Credentials) (string, error) {
	if err := verifyAgentBinaryVersion(hostBin, types.Version); err != nil {
		return "", err
	}
	// Unique first so a locked stale vN.exe never becomes the only successful copy.
	if s.Cfg.UseGuestAdditions() {
		s.stopGuestAgentService(creds)
	}

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
		err := s.Guest.CopyToDest(hostBin, dest)
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
	_, _ = s.Guest.Run(guest.UserSystem, `C:\Windows\System32\sc.exe`, []string{"stop", "QuarantineLabAgent"}, timeout)
	time.Sleep(2 * time.Second)
	_, _ = s.Guest.Run(guest.UserSystem, `C:\Windows\System32\cmd.exe`, []string{"/c", "taskkill /F /IM quarantine-agent.exe 2>nul"}, timeout)
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
	return "Set-ExecutionPolicy -Scope Process Bypass; & '" + guestpaths.StagingInstallScript() + "'"
}

// WaitForAgentVersion polls /health until Version matches want (or any version if want is empty).
func (s *Service) WaitForAgentVersion(ctx context.Context, want string) (*types.HealthResponse, error) {
	want = strings.TrimSpace(want)
	var last error
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		poll, cancel := context.WithTimeout(ctx, 8*time.Second)
		h, err := s.AgentHealthQuick(poll)
		cancel()
		if err == nil && h != nil {
			if want == "" || strings.TrimSpace(h.Version) == want {
				return h, nil
			}
			last = fmt.Errorf("agent still v%s (want v%s)", h.Version, want)
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			if last == nil {
				last = ctx.Err()
			}
			return nil, fmt.Errorf("wait for agent v%s: %w", want, last)
		case <-ticker.C:
		}
	}
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

// AgentHealthQuick is for UI/status polls: short path, no guest token sync.
func (s *Service) AgentHealthQuick(ctx context.Context) (*types.HealthResponse, error) {
	client, err := s.agentClient()
	if err != nil {
		return nil, err
	}
	return client.Health(ctx)
}

// ReadGuestFileBytes fetches an allowlisted path from the live guest via the agent.
// Used as a fast preview fallback when the changed-files sidecar has metadata only.
func (s *Service) ReadGuestFileBytes(ctx context.Context, guestPath string, maxBytes int64) ([]byte, error) {
	if s == nil || s.Cfg == nil || !s.Cfg.Agent.Enabled {
		return nil, fmt.Errorf("agent is not enabled")
	}
	client, err := s.agentClient()
	if err != nil {
		return nil, err
	}
	return client.GetFileBytes(ctx, guestPath, maxBytes)
}

// WaitForAgent polls /health until success or ctx is done.
func (s *Service) WaitForAgent(ctx context.Context) error {
	var last error
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		poll, cancel := context.WithTimeout(ctx, 8*time.Second)
		h, err := s.AgentHealthQuick(poll)
		cancel()
		if err == nil && h != nil {
			return nil
		}
		last = err
		select {
		case <-ctx.Done():
			if last == nil {
				last = ctx.Err()
			}
			return fmt.Errorf("%s", config.AgentUnreachableHint(last))
		case <-ticker.C:
		}
	}
}

// SyncWindowsGuestClock sets the Windows lab guest clock from the host (UTC)
// via agent SYSTEM exec. Gateway proxy/PCAP already use host-aligned time;
// without this, capturedAt stays ~20–30+ minutes behind network evidence and
// snapshot window filters look "wrong" even for short sessions.
func (s *Service) SyncWindowsGuestClock(ctx context.Context) error {
	if s == nil || s.Cfg == nil || !s.Cfg.Agent.Enabled {
		return fmt.Errorf("agent is not enabled")
	}
	client, err := s.agentClient()
	if err != nil {
		return err
	}
	stamp := time.Now().UTC().Format(time.RFC3339)
	// Parse as UTC round-trip then Set-Date in local time (SYSTEM).
	script := fmt.Sprintf(
		`$ErrorActionPreference='Stop'; $u=[datetime]::Parse('%s',[cultureinfo]::InvariantCulture,[System.Globalization.DateTimeStyles]::RoundtripKind); Set-Date -Date $u.ToLocalTime() | Out-Null; (Get-Date).ToUniversalTime().ToString('o')`,
		stamp,
	)
	resp, err := client.Exec(ctx, types.ExecRequest{
		Exe:       `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		Args:      []string{"-NoProfile", "-NonInteractive", "-Command", script},
		User:      "system",
		TimeoutMs: 45000,
	})
	if err != nil {
		return err
	}
	if resp.ExitCode != 0 {
		msg := strings.TrimSpace(resp.Stderr)
		if msg == "" {
			msg = strings.TrimSpace(resp.Stdout)
		}
		if msg == "" {
			msg = resp.Error
		}
		if msg == "" {
			msg = fmt.Sprintf("exit %d", resp.ExitCode)
		}
		return fmt.Errorf("Set-Date: %s", msg)
	}
	return nil
}

// ClearSysmonLog clears the guest Sysmon Operational channel via agent SYSTEM exec.
// Best used right after Launch so evidence only sees this session's events.
func (s *Service) ClearSysmonLog(ctx context.Context) error {
	if s == nil || s.Cfg == nil || !s.Cfg.Agent.Enabled {
		return fmt.Errorf("agent is not enabled")
	}
	logName := strings.TrimSpace(s.Cfg.Sysmon.EventLog)
	if logName == "" {
		logName = `Microsoft-Windows-Sysmon/Operational`
	}
	client, err := s.agentClient()
	if err != nil {
		return err
	}
	resp, err := client.Exec(ctx, types.ExecRequest{
		Exe:       `C:\Windows\System32\wevtutil.exe`,
		Args:      []string{"cl", logName},
		User:      "system",
		TimeoutMs: 60000,
	})
	if err != nil {
		return err
	}
	if resp.ExitCode != 0 {
		msg := strings.TrimSpace(resp.Stderr)
		if msg == "" {
			msg = strings.TrimSpace(resp.Stdout)
		}
		if msg == "" {
			msg = resp.Error
		}
		if msg == "" {
			msg = fmt.Sprintf("exit %d", resp.ExitCode)
		}
		return fmt.Errorf("wevtutil cl %s: %s", logName, msg)
	}
	return nil
}

func randomAgentToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}