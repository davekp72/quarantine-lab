package inbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quarantine-lab/quarantine/internal/agent/guestpaths"
	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/guest"
)

type recTransport struct {
	copied  [][2]string
	mkdirs  []string
	removed []string
}

func (r *recTransport) Name() string                { return config.TransportAgent }
func (r *recTransport) Ready(context.Context) error { return nil }
func (r *recTransport) Run(context.Context, string, string, []string, time.Duration) (string, error) {
	return "", nil
}
func (r *recTransport) CopyTo(_ context.Context, hostPath, guestDest string) error {
	r.copied = append(r.copied, [2]string{hostPath, guestDest})
	return nil
}
func (r *recTransport) CopyFrom(context.Context, string, string) error { return nil }
func (r *recTransport) Mkdir(_ context.Context, guestDir string) error {
	r.mkdirs = append(r.mkdirs, guestDir)
	return nil
}
func (r *recTransport) Remove(_ context.Context, guestPath string) error {
	r.removed = append(r.removed, guestPath)
	return nil
}

func TestInboxUsesAgentByDefault(t *testing.T) {
	t.Cleanup(func() { config.GuestAdditionsCLI = false })
	cfg := &config.Config{}
	cfg.Agent.Enabled = true
	s := New(cfg, nil)
	if s.Cfg.UseGuestAdditions() {
		t.Fatal("default should not use Guest Additions")
	}
	if GuestDir() != guestpaths.InboxDir() {
		t.Fatal(GuestDir())
	}
	config.GuestAdditionsCLI = true
	if !cfg.UseGuestAdditions() {
		t.Fatal("flag should select vbox share")
	}
	if guest.New(cfg, nil).Transport().Name() != config.TransportGuestControl {
		t.Fatal("guest transport should follow flag")
	}
}

func TestInboxAgentOpenCopiesWithoutShare(t *testing.T) {
	t.Cleanup(func() { config.GuestAdditionsCLI = false })
	host := t.TempDir()
	sample := filepath.Join(host, "sample.bin")
	if err := os.WriteFile(sample, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Agent.Enabled = true
	cfg.Inbox.HostPath = host
	s := New(cfg, nil)
	rec := &recTransport{}
	s.Guest.SetTransport(rec)
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	if s.mode != "agent" {
		t.Fatalf("mode=%q", s.mode)
	}
	if !strings.Contains(s.Status(), "agent") {
		t.Fatalf("status=%q", s.Status())
	}
	if len(rec.copied) != 1 {
		t.Fatalf("copied=%v", rec.copied)
	}
	if rec.copied[0][0] != sample {
		t.Fatalf("host path %q", rec.copied[0][0])
	}
	wantDest := guestpaths.GuestJoin(guestpaths.InboxDir(), "sample.bin")
	if !strings.EqualFold(rec.copied[0][1], wantDest) {
		t.Fatalf("dest=%q want %q", rec.copied[0][1], wantDest)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if len(rec.removed) != 1 {
		t.Fatalf("removed=%v", rec.removed)
	}
}
