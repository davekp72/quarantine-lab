package guestpaths

import (
	"strings"
	"testing"
)

func TestHiveDirNotPublic(t *testing.T) {
	dir := HiveDir("Evidence-case")
	if strings.Contains(strings.ToLower(dir), `\users\public\`) {
		t.Fatalf("hive dir must not be under Public: %s", dir)
	}
	if !strings.HasPrefix(strings.ToLower(dir), strings.ToLower(DataDir)) {
		t.Fatalf("hive dir must be under ProgramData: %s", dir)
	}
	if !IsHivePath(dir + `\SAM`) {
		t.Fatal("expected SAM path to be recognized")
	}
	if IsHivePath(`C:\Users\Public\Quarantine\hives\SAM`) {
		t.Fatal("legacy Public hive path must not pass IsHivePath")
	}
}

func TestTokenNotPublic(t *testing.T) {
	if strings.Contains(strings.ToLower(TokenPath()), `\users\public\`) {
		t.Fatalf("token path under Public: %s", TokenPath())
	}
	if strings.Contains(strings.ToLower(InstallExe()), `\users\public\`) {
		t.Fatalf("install exe under Public: %s", InstallExe())
	}
}

func TestStagingTokenIsPublicOneShot(t *testing.T) {
	if !strings.Contains(strings.ToLower(StagingTokenPath()), `\users\public\`) {
		t.Fatalf("staging token must be guestcontrol-writable under Public: %s", StagingTokenPath())
	}
	if !strings.Contains(strings.ToLower(SyncExportPath()), `\users\public\`) {
		t.Fatalf("sync export must be guestcontrol-readable under Public: %s", SyncExportPath())
	}
	foundStaging := false
	for _, p := range TokenCopyCandidates() {
		if p == StagingTokenPath() {
			foundStaging = true
		}
		if p == TokenPath() && strings.Contains(strings.ToLower(p), `\users\public\`) {
			t.Fatal("durable token must not be listed as a Public path")
		}
	}
	if !foundStaging {
		t.Fatal("expected staging token among copy candidates")
	}
}

func TestHiveFilePathRejectsTraversal(t *testing.T) {
	p, err := HiveFilePath("Evidence-x", "SAM")
	if err != nil {
		t.Fatal(err)
	}
	if !IsHivePath(p) {
		t.Fatalf("expected hive path: %s", p)
	}
	if _, err := HiveFilePath("Evidence-x", `..\..\Windows\System32\config\SAM`); err == nil {
		t.Fatal("expected traversal reject")
	}
	if IsHivePath(`C:\ProgramData\QuarantineLab\hives\..\agent-token.txt`) {
		t.Fatal("cleaned path must not treat token as a hive file")
	}
	if ShouldDeleteHiveDir(`C:\Users\Public\Quarantine\hives\..\..\Windows`) {
		t.Fatal("must not delete paths that clean outside hive roots")
	}
	if ShouldDeleteHiveDir(`C:\Windows\System32`) {
		t.Fatal("must not delete arbitrary dirs")
	}
	if !ShouldDeleteHiveDir(`C:\Users\Public\Quarantine\hives\Evidence-x`) {
		t.Fatal("legacy public hive dir should be deleted after pull")
	}
	if !IsProtectedRoot(DataDir) || !IsProtectedRoot(InstallDir+`\quarantine-agent.exe`) {
		t.Fatal("expected protected roots")
	}
}
