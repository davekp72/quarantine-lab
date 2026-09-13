package inbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quarantine-lab/quarantine/internal/agent/guestpaths"
	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/guest"
	"github.com/quarantine-lab/quarantine/internal/vbox"
)

// Service manages sample delivery into the guest.
type Service struct {
	Cfg   *config.Config
	VBox  *vbox.Client
	Guest *guest.Client
	mode  string // agent | vboxshare | ""
}

// New creates an inbox service.
func New(cfg *config.Config, vb *vbox.Client) *Service {
	return &Service{Cfg: cfg, VBox: vb, Guest: guest.New(cfg, vb)}
}

// GuestDir is the agent-delivered inbox path inside Windows.
func GuestDir() string {
	return guestpaths.InboxDir()
}

// Open delivers inbox files (agent) or mounts a transient VBOXSVR share (Guest Additions).
func (s *Service) Open() error {
	if s.Cfg.UseGuestAdditions() {
		if s.mode == "vboxshare" {
			return nil
		}
		if err := s.VBox.SharedFolderAdd(s.Cfg.VMName, s.Cfg.Inbox.ShareName, s.Cfg.Inbox.HostPath, s.Cfg.Inbox.ReadOnly); err != nil {
			return fmt.Errorf("open inbox: %w", err)
		}
		s.mode = "vboxshare"
		return nil
	}
	host := strings.TrimSpace(s.Cfg.Inbox.HostPath)
	if host == "" {
		return fmt.Errorf("inbox.hostPath is empty")
	}
	entries, err := os.ReadDir(host)
	if err != nil {
		if os.IsNotExist(err) {
			if mkErr := os.MkdirAll(host, 0o755); mkErr != nil {
				return mkErr
			}
			entries = nil
		} else {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	destDir := guestpaths.InboxDir()
	_ = s.Guest.Transport().Mkdir(ctx, destDir)
	copied := 0
	var delivered []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		src := filepath.Join(host, e.Name())
		dest := guestpaths.GuestJoin(destDir, e.Name())
		info, err := os.Stat(src)
		if err != nil {
			return fmt.Errorf("deliver %s: %w", e.Name(), err)
		}
		if err := s.Guest.CopyToDest(src, dest); err != nil {
			return fmt.Errorf("deliver %s: %w", e.Name(), err)
		}
		delivered = append(delivered, fmt.Sprintf("%s (%d bytes)", e.Name(), info.Size()))
		copied++
	}
	s.mode = "agent"
	if copied == 0 {
		fmt.Printf("inbox open: no files in %s (stage with Copy-Item, then inbox open again)\n", host)
		return nil
	}
	fmt.Printf("inbox open: delivered %d file(s) via agent → %s\n", copied, destDir)
	for _, d := range delivered {
		fmt.Printf("  - %s\n", d)
	}
	return nil
}

// Close removes the VBOXSVR share or deletes the guest inbox directory.
func (s *Service) Close() error {
	if s.mode == "vboxshare" || s.Cfg.UseGuestAdditions() {
		if err := s.VBox.SharedFolderRemove(s.Cfg.VMName, s.Cfg.Inbox.ShareName); err != nil {
			if s.mode == "" {
				return err
			}
		}
		s.mode = ""
		return nil
	}
	if err := s.Guest.Remove(guestpaths.InboxDir()); err != nil {
		return err
	}
	s.mode = ""
	return nil
}

// Status returns open/closed plus transport.
func (s *Service) Status() string {
	if s.mode == "vboxshare" {
		return "open (vboxshare \\\\VBOXSVR\\" + s.Cfg.Inbox.ShareName + ")"
	}
	if s.mode == "agent" {
		return "open (agent " + guestpaths.InboxDir() + ")"
	}
	if s.Cfg.UseGuestAdditions() {
		return "closed (vboxshare)"
	}
	return "closed (agent " + guestpaths.InboxDir() + ")"
}
