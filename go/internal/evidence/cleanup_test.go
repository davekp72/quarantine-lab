package evidence

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/quarantine-lab/quarantine/internal/config"
)

func TestRemoveSnapshotArtifactsKeepsCases(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{Manifest: config.ManifestConfig{LogDir: dir}}
	s := &Service{Cfg: cfg}
	name := "Evidence-test"
	safe := config.SafeSnapshotFileName(name)

	sidecar := filepath.Join(dir, safe+"-changed-files.json")
	if err := os.WriteFile(sidecar, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	netDir := filepath.Join(dir, safe+"-network")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(netDir, "capture.pcap"), []byte("pcap"), 0o644); err != nil {
		t.Fatal(err)
	}
	loose := filepath.Join(dir, "diff-CleanSession-vs-"+safe+".diff.json")
	if err := os.WriteFile(loose, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}

	caseDir := filepath.Join(dir, "cases", "20260101T000000Z-CleanSession-vs-"+safe)
	if err := os.MkdirAll(filepath.Join(caseDir, "network"), 0o755); err != nil {
		t.Fatal(err)
	}
	caseMeta := filepath.Join(caseDir, "meta.json")
	if err := os.WriteFile(caseMeta, []byte(`{"id":"kept"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caseDir, "network", "capture.pcap"), []byte("kept"), 0o644); err != nil {
		t.Fatal(err)
	}

	s.RemoveSnapshotArtifacts(name)

	if _, err := os.Stat(sidecar); err == nil {
		t.Fatal("sidecar should be removed")
	}
	if _, err := os.Stat(netDir); err == nil {
		t.Fatal("snapshot network dir should be removed")
	}
	if _, err := os.Stat(loose); err == nil {
		t.Fatal("loose diff json should be removed")
	}
	if _, err := os.Stat(caseMeta); err != nil {
		t.Fatalf("case pack must remain: %v", err)
	}
	if raw, err := os.ReadFile(filepath.Join(caseDir, "network", "capture.pcap")); err != nil || string(raw) != "kept" {
		t.Fatalf("case pcap=%q err=%v", raw, err)
	}
}
