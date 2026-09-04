package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quarantine-lab/quarantine/internal/guest"
	"github.com/quarantine-lab/quarantine/internal/jsonutil"
)

func (s *Service) guestDir() string {
	dir := strings.TrimSpace(s.Cfg.Guest.CopyTargetDir)
	if dir == "" {
		return `C:\Users\Public\Quarantine`
	}
	return dir
}

func (s *Service) captureTimeout() time.Duration {
	ms := s.Cfg.Guest.TimeoutMs
	if ms <= 0 {
		ms = 900000
	}
	return time.Duration(ms) * time.Millisecond
}

func (s *Service) manifestScript(name string) string {
	return filepath.Join(s.ProjectRoot, "manifest", name)
}

func (s *Service) deployToGuest(hostPath, guestDir string, creds guest.Credentials) error {
	if _, err := os.Stat(hostPath); err != nil {
		return fmt.Errorf("missing script %s: %w", hostPath, err)
	}
	return s.Guest.CopyTo(hostPath, guestDir, creds)
}

func (s *Service) deployManifestScript(leaf string, creds guest.Credentials) error {
	return s.deployToGuest(s.manifestScript(leaf), s.guestDir(), creds)
}

func (s *Service) deployPrivDeps(creds guest.Credentials) error {
	return s.deployToGuest(s.manifestScript("QuarantineGuestPriv.psm1"), s.guestDir(), creds)
}

func (s *Service) runGuestPS(creds guest.Credentials, scriptLeaf string, args []string) (string, error) {
	guestDir := s.guestDir()
	scriptPath := filepath.Join(guestDir, scriptLeaf)
	psArgs := append([]string{
		"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", scriptPath,
	}, args...)
	return s.VBox.GuestControlRun(
		s.Cfg.VMName, creds.Username, creds.Password,
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		psArgs, s.captureTimeout(),
	)
}

func (s *Service) copyFromGuest(guestPath, hostPath string, creds guest.Credentials) error {
	if err := os.MkdirAll(filepath.Dir(hostPath), 0o755); err != nil {
		return err
	}
	return s.Guest.CopyFrom(guestPath, hostPath, creds)
}

// MarkLiveSnapshot captures live USN/event sidecars via guestcontrol (no host PowerShell).
// Registry hives require the quarantine agent (MarkLiveSnapshot with agent.enabled).
func (s *Service) markLiveSnapshotLegacy(snapshotName string) (string, error) {
	snap := s.Cfg.ResolveSnapshotName(snapshotName)

	isEvidence := strings.HasPrefix(strings.ToLower(snap), "evidence-")
	baseline := strings.TrimSpace(s.Cfg.Manifest.SessionBaselineSnapshot)

	if isEvidence && baseline != "" {
		if err := s.captureEvidenceEvents(snap, baseline); err != nil {
			return "", err
		}
	} else {
		if err := s.setUsnBaseline(snap); err != nil {
			return "", err
		}
		if err := s.saveBaselineEventMarkerSidecars(snap); err != nil {
			return "", err
		}
	}

	if err := s.ensurePayloadSidecar(snap); err != nil {
		return "", err
	}
	return s.PublishFromSidecars(snap)
}

func (s *Service) setUsnBaseline(snapshotName string) error {
	creds := s.Guest.GuestCreds()
	if err := s.deployManifestScript("Set-QuarantineGuestUsnBaseline.ps1", creds); err != nil {
		return err
	}
	if err := s.deployPrivDeps(creds); err != nil {
		return err
	}
	if _, err := s.runGuestPS(creds, "Set-QuarantineGuestUsnBaseline.ps1", nil); err != nil {
		return fmt.Errorf("USN baseline: %w", err)
	}
	guestBaseline := filepath.Join(s.guestDir(), "usn-baseline.json")
	hostBaseline := s.Cfg.SidecarPath(snapshotName, "-baseline.json")
	return s.copyFromGuest(guestBaseline, hostBaseline, creds)
}

func (s *Service) saveBaselineEventMarkerSidecars(snapshotName string) error {
	hostBaseline := s.Cfg.SidecarPath(snapshotName, "-baseline.json")
	raw, err := os.ReadFile(hostBaseline)
	if err != nil {
		return err
	}
	var baseline map[string]any
	if err := jsonutil.Unmarshal(raw, &baseline); err != nil {
		return err
	}
	recordedAt := time.Now().UTC().Format(time.RFC3339)
	if v, ok := baseline["recordedAt"].(string); ok && v != "" {
		recordedAt = v
	}
	startUsn, _ := baseline["startUsn"].(string)

	writeMarker := func(path, msg string) error {
		marker := map[string]any{
			"available":  true,
			"eventCount": 0,
			"message":    msg,
			"baselineAt": recordedAt,
			"recordedAt": recordedAt,
			"events":     []any{},
		}
		if strings.Contains(path, "usn") && startUsn != "" {
			marker["startUsn"] = startUsn
		}
		out, err := json.MarshalIndent(marker, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(path, out, 0o644)
	}

	if err := writeMarker(s.Cfg.SidecarPath(snapshotName, "-usn-delta.json"), "Baseline snapshot — USN delta starts after this point."); err != nil {
		return err
	}
	if err := writeMarker(s.Cfg.SidecarPath(snapshotName, "-sysmon.json"), "Baseline snapshot — Sysmon events start after this point."); err != nil {
		return err
	}
	return writeMarker(s.Cfg.SidecarPath(snapshotName, "-service-installs.json"), "Baseline snapshot — service install events start after this point.")
}

func (s *Service) publishUsnBaselineFromHost(hostBaseline string) error {
	creds := s.Guest.GuestCreds()
	guestDir := s.guestDir()
	if err := s.Guest.CopyTo(hostBaseline, guestDir, creds); err != nil {
		return err
	}
	uploaded := filepath.Join(guestDir, filepath.Base(hostBaseline))
	target := filepath.Join(guestDir, "usn-baseline.json")
	if strings.EqualFold(filepath.Base(hostBaseline), "usn-baseline.json") {
		return nil
	}
	up := strings.ReplaceAll(uploaded, `'`, `''`)
	tg := strings.ReplaceAll(target, `'`, `''`)
	ps := fmt.Sprintf("Move-Item -LiteralPath '%s' -Destination '%s' -Force", up, tg)
	_, err := s.VBox.GuestControlRun(
		s.Cfg.VMName, creds.Username, creds.Password,
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		[]string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps},
		s.captureTimeout(),
	)
	return err
}

type exportStep struct {
	scriptLeaf string
	guestOut   string
}

func (s *Service) runPrivilegedExportSteps(steps []exportStep) error {
	creds := s.Guest.GuestCreds()
	for _, step := range steps {
		if err := s.deployManifestScript(step.scriptLeaf, creds); err != nil {
			return err
		}
		if err := s.deployPrivDeps(creds); err != nil {
			return err
		}
		if _, err := s.runGuestPS(creds, step.scriptLeaf, []string{"-OutFile", step.guestOut}); err != nil {
			return fmt.Errorf("%s: %w", step.scriptLeaf, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	return nil
}

func (s *Service) captureEvidenceEvents(snapshotName, fromBaseline string) error {
	fromBaseline = s.Cfg.ResolveSnapshotName(fromBaseline)
	hostBaseline := s.Cfg.SidecarPath(fromBaseline, "-baseline.json")
	if _, err := os.Stat(hostBaseline); err != nil {
		return fmt.Errorf("USN baseline missing for %q (%s)", fromBaseline, hostBaseline)
	}
	if err := s.publishUsnBaselineFromHost(hostBaseline); err != nil {
		return fmt.Errorf("publish USN baseline: %w", err)
	}

	guestDir := s.guestDir()
	steps := []exportStep{
		{"Get-QuarantineGuestUsnDelta.ps1", filepath.Join(guestDir, "usn-delta-export.json")},
		{"Get-QuarantineGuestSysmonEvents.ps1", filepath.Join(guestDir, "sysmon-events-export.json")},
		{"Get-QuarantineGuestServiceInstallEvents.ps1", filepath.Join(guestDir, "service-install-events-export.json")},
		{"Export-QuarantineGuestChangedFiles.ps1", filepath.Join(guestDir, "changed-files-export.json")},
	}
	if err := s.runPrivilegedExportSteps(steps); err != nil {
		return err
	}

	creds := s.Guest.GuestCreds()
	copies := []struct{ guest, host string }{
		{steps[0].guestOut, s.Cfg.SidecarPath(snapshotName, "-usn-delta.json")},
		{steps[1].guestOut, s.Cfg.SidecarPath(snapshotName, "-sysmon.json")},
		{steps[2].guestOut, s.Cfg.SidecarPath(snapshotName, "-service-installs.json")},
		{steps[3].guestOut, s.Cfg.SidecarPath(snapshotName, "-changed-files.json")},
	}
	for _, c := range copies {
		_ = s.copyFromGuest(c.guest, c.host, creds)
	}
	return nil
}
