package unattend

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// StageExtras are optional binaries/secrets copied onto the setup ISO (not the 1.44MB floppy).
type StageExtras struct {
	AgentExe     string
	AgentToken   string
	AgentPort    int
	SysmonExe    string
	SysmonConfig string
}

// StageFiles copies first-logon helpers + rendered answer file into mediaDir
// (usually {vmDataDir}/unattend/media), builds floppy/ISO sidecars, and when
// windowsISO is set, builds a bootable Win11 setup ISO with autounattend.xml
// in the root (required for reliable EFI unattended install).
func StageFiles(projectRoot, mediaDir, renderedAutounattend, windowsISO string, payloadUser, labAdmin, guestPassword, payloadPassword string, extras StageExtras) (floppyPath string, notes []string, err error) {
	if strings.TrimSpace(renderedAutounattend) == "" {
		return "", nil, fmt.Errorf("rendered autounattend path is empty")
	}
	if _, err := os.Stat(renderedAutounattend); err != nil {
		return "", nil, fmt.Errorf("rendered autounattend: %w", err)
	}
	if err := os.MkdirAll(mediaDir, 0o700); err != nil {
		return "", nil, err
	}

	entries, _ := os.ReadDir(mediaDir)
	for _, e := range entries {
		_ = os.RemoveAll(filepath.Join(mediaDir, e.Name()))
	}

	if err := copyFile(renderedAutounattend, filepath.Join(mediaDir, "autounattend.xml")); err != nil {
		return "", nil, err
	}
	notes = append(notes, "staged autounattend.xml")

	firstLogon := filepath.Join(projectRoot, "templates", "firstlogon", "Invoke-QuarantineFirstLogon.ps1")
	if err := copyFile(firstLogon, filepath.Join(mediaDir, "Invoke-QuarantineFirstLogon.ps1")); err != nil {
		return "", nil, fmt.Errorf("firstlogon script: %w", err)
	}
	notes = append(notes, "staged Invoke-QuarantineFirstLogon.ps1")

	qDir := filepath.Join(mediaDir, "Quarantine")
	if err := os.MkdirAll(qDir, 0o700); err != nil {
		return "", nil, err
	}

	repl := map[string]string{
		"__GUEST_USERNAME__":   labAdmin,
		"__GUEST_PASSWORD__":   strings.ReplaceAll(guestPassword, "'", "''"),
		"__PAYLOAD_USERNAME__": payloadUser,
		"__PAYLOAD_PASSWORD__": strings.ReplaceAll(payloadPassword, "'", "''"),
	}
	replCmd := map[string]string{
		"__GUEST_USERNAME__":   labAdmin,
		"__GUEST_PASSWORD__":   guestPassword,
		"__PAYLOAD_USERNAME__": payloadUser,
		"__PAYLOAD_PASSWORD__": payloadPassword,
	}
	for _, name := range []string{
		"Finish-LabAdmin.ps1",
		"SetupComplete.cmd",
		"Install-LabAdminScripts.cmd",
	} {
		src := filepath.Join(projectRoot, "templates", "firstlogon", name)
		raw, err := os.ReadFile(src)
		if err != nil {
			return "", notes, fmt.Errorf("read %s: %w", name, err)
		}
		s := string(raw)
		use := replCmd
		if strings.HasSuffix(name, ".ps1") {
			use = repl
		}
		for k, v := range use {
			s = strings.ReplaceAll(s, k, v)
		}
		if err := os.WriteFile(filepath.Join(qDir, name), []byte(s), 0o600); err != nil {
			return "", notes, err
		}
		notes = append(notes, "staged Quarantine/"+name)
	}

	oemScripts := filepath.Join(mediaDir, "$OEM$", "$$", "Setup", "Scripts")
	if err := os.MkdirAll(oemScripts, 0o755); err != nil {
		return "", notes, err
	}
	if err := copyFile(filepath.Join(qDir, "SetupComplete.cmd"), filepath.Join(oemScripts, "SetupComplete.cmd")); err != nil {
		return "", notes, err
	}
	if err := copyFile(filepath.Join(qDir, "Finish-LabAdmin.ps1"), filepath.Join(oemScripts, "Finish-LabAdmin.ps1")); err != nil {
		return "", notes, err
	}
	if err := copyFile(filepath.Join(mediaDir, "Invoke-QuarantineFirstLogon.ps1"), filepath.Join(oemScripts, "Invoke-QuarantineFirstLogon.ps1")); err != nil {
		return "", notes, err
	}
	notes = append(notes, "staged $OEM$ SetupComplete/Finish-LabAdmin")

	optional := []string{
		filepath.Join(projectRoot, "guest", "Invoke-QuarantineGuestProvision.ps1"),
		filepath.Join(projectRoot, "guest", "Grant-QuarantineGuestEventLogAccess.ps1"),
		filepath.Join(projectRoot, "network", "guest", "Configure-QuarantineGuestNetwork.ps1"),
		filepath.Join(projectRoot, "network", "guest", "Harden-QuarantineGuestNetwork.ps1"),
		filepath.Join(projectRoot, "network", "guest", "Install-QuarantineProxyCA.ps1"),
		filepath.Join(projectRoot, "network", "guest", "Disable-QuarantineAutoLogon.ps1"),
		filepath.Join(projectRoot, "network", "guest", "Disable-QuarantineGuestUpdates.ps1"),
		filepath.Join(projectRoot, "manifest", "Install-QuarantineAgent.ps1"),
		filepath.Join(projectRoot, "guest", "Install-QuarantineSysmon.ps1"),
		filepath.Join(projectRoot, "network", "proxy", "mitmproxy-ca-cert.cer"),
		filepath.Join(projectRoot, "config", "sysmon", "quarantine-lab.xml"),
	}
	for _, src := range optional {
		if _, err := os.Stat(src); err != nil {
			notes = append(notes, "skip "+filepath.Base(src))
			continue
		}
		dest := filepath.Join(qDir, filepath.Base(src))
		if err := copyFile(src, dest); err != nil {
			return "", notes, err
		}
		notes = append(notes, "staged Quarantine/"+filepath.Base(src))
	}

	hints, err := json.MarshalIndent(map[string]string{
		"payloadUser": payloadUser,
		"labAdmin":    labAdmin,
		"networkMode": "gateway",
		"source":      "firstlogon-media",
	}, "", "  ")
	if err != nil {
		return "", notes, err
	}
	if err := os.WriteFile(filepath.Join(qDir, "guest-provision.json"), append(hints, '\n'), 0o600); err != nil {
		return "", notes, err
	}
	notes = append(notes, "staged Quarantine/guest-provision.json")

	binNotes, binErr := stageGuestBinaries(qDir, payloadUser, extras)
	notes = append(notes, binNotes...)
	if binErr != nil {
		return "", notes, binErr
	}

	finishCmd := "@echo off\r\n" +
		"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command " +
		"\"Start-Process -FilePath powershell.exe -Verb RunAs -Wait -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \\\"%Public%\\Quarantine\\Invoke-QuarantineGuestProvision.ps1\\\"'\"\r\n"
	if err := os.WriteFile(filepath.Join(qDir, "Finish-QuarantineProvision.cmd"), []byte(finishCmd), 0o600); err != nil {
		return "", notes, err
	}

	floppyPath = filepath.Join(filepath.Dir(mediaDir), "unattend.img")
	if err := WriteFloppyFromDir(floppyPath, mediaDir); err != nil {
		return "", notes, err
	}
	if info, err := os.Stat(floppyPath); err == nil {
		notes = append(notes, fmt.Sprintf("wrote %s (%d bytes)", floppyPath, info.Size()))
	}

	isoPath := filepath.Join(filepath.Dir(mediaDir), "unattend.iso")
	if err := WriteISOFromDir(isoPath, mediaDir); err != nil {
		notes = append(notes, "unattend sidecar ISO skipped: "+err.Error())
	} else if info, err := os.Stat(isoPath); err == nil {
		notes = append(notes, fmt.Sprintf("wrote %s (%d bytes)", isoPath, info.Size()))
	}

	if strings.TrimSpace(windowsISO) != "" {
		if _, err := os.Stat(windowsISO); err == nil {
			staging := filepath.Join(filepath.Dir(mediaDir), "setup-staging")
			setupISO := filepath.Join(filepath.Dir(mediaDir), "Win11-setup.iso")
			notes = append(notes, "building bootable setup ISO (first run caches staging; can take several minutes)...")
			if err := BuildBootableSetupISO(windowsISO, mediaDir, staging, setupISO); err != nil {
				return floppyPath, notes, fmt.Errorf("bootable setup ISO: %w", err)
			}
			if info, err := os.Stat(setupISO); err == nil {
				notes = append(notes, fmt.Sprintf("wrote %s (%d bytes) - attach as the install DVD", setupISO, info.Size()))
			}
		} else {
			notes = append(notes, "windows ISO not found for setup remaster: "+windowsISO)
		}
	}

	return floppyPath, notes, nil
}

func stageGuestBinaries(qDir, payloadUser string, extras StageExtras) (notes []string, err error) {
	if strings.TrimSpace(extras.AgentExe) != "" {
		if _, err := os.Stat(extras.AgentExe); err != nil {
			notes = append(notes, "skip quarantine-agent.exe: "+err.Error())
		} else {
			staging := filepath.Join(qDir, "agent-staging")
			if err := os.MkdirAll(staging, 0o700); err != nil {
				return notes, err
			}
			if err := copyFile(extras.AgentExe, filepath.Join(staging, "quarantine-agent.exe")); err != nil {
				return notes, fmt.Errorf("stage agent binary: %w", err)
			}
			notes = append(notes, "staged Quarantine/agent-staging/quarantine-agent.exe")
			if tok := strings.TrimSpace(extras.AgentToken); tok != "" {
				if err := os.WriteFile(filepath.Join(staging, "agent-token.txt"), []byte(tok+"\n"), 0o600); err != nil {
					return notes, err
				}
				notes = append(notes, "staged Quarantine/agent-staging/agent-token.txt")
			}
			port := extras.AgentPort
			if port <= 0 {
				port = 9443
			}
			installCfg, mErr := json.MarshalIndent(map[string]any{
				"binary":      `C:\Users\Public\Quarantine\agent-staging\quarantine-agent.exe`,
				"port":        port,
				"payloadUser": payloadUser,
			}, "", "  ")
			if mErr != nil {
				return notes, mErr
			}
			if err := os.WriteFile(filepath.Join(qDir, "agent-install.json"), append(installCfg, '\n'), 0o600); err != nil {
				return notes, err
			}
			notes = append(notes, "staged Quarantine/agent-install.json")
		}
	}

	sysmonDir := filepath.Join(qDir, "sysmon")
	copiedSysmonDir := false
	ensureSysmonDir := func() error {
		if copiedSysmonDir {
			return nil
		}
		if err := os.MkdirAll(sysmonDir, 0o700); err != nil {
			return err
		}
		copiedSysmonDir = true
		return nil
	}
	sysmonScript := filepath.Join(qDir, "Install-QuarantineSysmon.ps1")
	if _, err := os.Stat(sysmonScript); err == nil {
		if err := ensureSysmonDir(); err != nil {
			return notes, err
		}
		if err := copyFile(sysmonScript, filepath.Join(sysmonDir, "Install-QuarantineSysmon.ps1")); err != nil {
			return notes, err
		}
	}
	if p := strings.TrimSpace(extras.SysmonConfig); p != "" {
		if _, err := os.Stat(p); err == nil {
			if err := ensureSysmonDir(); err != nil {
				return notes, err
			}
			destName := filepath.Base(p)
			if destName == "" {
				destName = "quarantine-lab.xml"
			}
			if err := copyFile(p, filepath.Join(sysmonDir, destName)); err != nil {
				return notes, err
			}
			notes = append(notes, "staged Quarantine/sysmon/"+destName)
		}
	}
	if p := strings.TrimSpace(extras.SysmonExe); p != "" {
		if _, err := os.Stat(p); err == nil {
			if err := ensureSysmonDir(); err != nil {
				return notes, err
			}
			if err := copyFile(p, filepath.Join(sysmonDir, "Sysmon64.exe")); err != nil {
				return notes, fmt.Errorf("stage Sysmon: %w", err)
			}
			notes = append(notes, "staged Quarantine/sysmon/Sysmon64.exe")
		} else {
			notes = append(notes, "skip Sysmon64.exe")
		}
	}
	return notes, nil
}
