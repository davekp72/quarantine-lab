package inbox

import (
	"fmt"

	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/vbox"
)

// Service manages transient inbox shared folder.
type Service struct {
	Cfg  *config.Config
	VBox *vbox.Client
	open bool
}

// New creates inbox service.
func New(cfg *config.Config, vb *vbox.Client) *Service {
	return &Service{Cfg: cfg, VBox: vb}
}

// Open mounts read-only inbox share.
func (s *Service) Open() error {
	if s.open {
		return nil
	}
	if err := s.VBox.SharedFolderAdd(s.Cfg.VMName, s.Cfg.Inbox.ShareName, s.Cfg.Inbox.HostPath, s.Cfg.Inbox.ReadOnly); err != nil {
		return fmt.Errorf("open inbox: %w", err)
	}
	s.open = true
	return nil
}

// Close removes inbox share.
func (s *Service) Close() error {
	if !s.open {
		return nil
	}
	if err := s.VBox.SharedFolderRemove(s.Cfg.VMName, s.Cfg.Inbox.ShareName); err != nil {
		return err
	}
	s.open = false
	return nil
}

// Status returns open/closed.
func (s *Service) Status() string {
	if s.open {
		return "open"
	}
	return "closed"
}
