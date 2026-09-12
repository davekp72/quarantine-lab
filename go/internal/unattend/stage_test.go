package unattend

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStageFilesBuildsFloppy(t *testing.T) {
	project := t.TempDir()
	tmpl := filepath.Join(project, "templates", "firstlogon")
	if err := os.MkdirAll(tmpl, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpl, "Invoke-QuarantineFirstLogon.ps1"), []byte("# first\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Finish-LabAdmin.ps1", "SetupComplete.cmd", "Install-LabAdminScripts.cmd"} {
		if err := os.WriteFile(filepath.Join(tmpl, name), []byte("placeholder __GUEST_USERNAME__\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	guestDir := filepath.Join(project, "guest")
	if err := os.MkdirAll(guestDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(guestDir, "Invoke-QuarantineGuestProvision.ps1"), []byte("# prov\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	data := t.TempDir()
	rendered := filepath.Join(data, "autounattend.xml")
	if err := os.WriteFile(rendered, []byte("<unattend/>"), 0o600); err != nil {
		t.Fatal(err)
	}
	media := filepath.Join(data, "media")
	floppy, notes, err := StageFiles(project, media, rendered, "", "analyst", "quarantine", "GuestPass1!", "PayloadPass1!", StageExtras{})
	if err != nil {
		t.Fatalf("StageFiles: %v\nnotes=%v", err, notes)
	}
	if _, err := os.Stat(floppy); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(floppy)
	if info.Size() != floppySize {
		t.Fatalf("floppy size %d want %d", info.Size(), floppySize)
	}
	if _, err := os.Stat(filepath.Join(media, "autounattend.xml")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(media, "Quarantine", "Invoke-QuarantineGuestProvision.ps1")); err != nil {
		t.Fatal(err)
	}
	iso := filepath.Join(filepath.Dir(media), "unattend.iso")
	if _, err := os.Stat(iso); err != nil {
		t.Fatalf("expected unattend.iso: %v", err)
	}
}

func TestStageFilesIncludesAgentOnISONotFloppy(t *testing.T) {
	project := t.TempDir()
	tmpl := filepath.Join(project, "templates", "firstlogon")
	if err := os.MkdirAll(tmpl, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpl, "Invoke-QuarantineFirstLogon.ps1"), []byte("# first\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Finish-LabAdmin.ps1", "SetupComplete.cmd", "Install-LabAdminScripts.cmd"} {
		if err := os.WriteFile(filepath.Join(tmpl, name), []byte("placeholder __GUEST_USERNAME__\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	exe := filepath.Join(project, "go", "quarantine-agent.exe")
	if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 512*1024)
	for i := range payload {
		payload[i] = 'A'
	}
	if err := os.WriteFile(exe, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	data := t.TempDir()
	rendered := filepath.Join(data, "autounattend.xml")
	if err := os.WriteFile(rendered, []byte("<unattend/>"), 0o600); err != nil {
		t.Fatal(err)
	}
	media := filepath.Join(data, "media")
	floppy, notes, err := StageFiles(project, media, rendered, "", "analyst", "Administrator", "GuestPass1!", "PayloadPass1!", StageExtras{
		AgentExe:   exe,
		AgentToken: "test-token-value",
		AgentPort:  9443,
	})
	if err != nil {
		t.Fatalf("StageFiles: %v\nnotes=%v", err, notes)
	}
	info, _ := os.Stat(floppy)
	if info.Size() != floppySize {
		t.Fatalf("floppy size %d want %d", info.Size(), floppySize)
	}
	staged := filepath.Join(media, "Quarantine", "agent-staging", "quarantine-agent.exe")
	if _, err := os.Stat(staged); err != nil {
		t.Fatalf("agent missing from ISO media: %v", err)
	}
	tok, err := os.ReadFile(filepath.Join(media, "Quarantine", "agent-staging", "agent-token.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(tok)) != "test-token-value" {
		t.Fatalf("token %q", tok)
	}
}
