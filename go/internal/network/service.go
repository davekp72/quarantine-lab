package network

import (
	"fmt"

	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/vbox"
)

// Service manages VM network modes.
type Service struct {
	Cfg  *config.Config
	VBox *vbox.Client
}

// New creates network service.
func New(cfg *config.Config, vb *vbox.Client) *Service {
	return &Service{Cfg: cfg, VBox: vb}
}

// EnsureAgentPortForward adds NAT rule host:port -> guest:port for quarantine-agent.
func (s *Service) EnsureAgentPortForward() error {
	if !s.Cfg.Agent.Enabled {
		return nil
	}
	port := s.Cfg.Agent.Port
	if port <= 0 {
		port = 9443
	}
	name := s.Cfg.Agent.NatRuleName
	if name == "" {
		name = "quarantine-agent"
	}
	rule := fmt.Sprintf("%s,tcp,,%d,,%d", name, port, port)

	// Remove stale rule (ignore if missing).
	_ = s.VBox.NatPFDelete(s.Cfg.VMName, name)
	return s.VBox.NatPFAdd(s.Cfg.VMName, rule)
}

// RemoveAgentPortForward deletes the agent NAT rule.
func (s *Service) RemoveAgentPortForward() error {
	if !s.Cfg.Agent.Enabled {
		return nil
	}
	name := s.Cfg.Agent.NatRuleName
	if name == "" {
		name = "quarantine-agent"
	}
	return s.VBox.NatPFDelete(s.Cfg.VMName, name)
}

// SetMode applies network mode to VM NIC1.
func (s *Service) SetMode(mode string) error {
	vm := s.Cfg.VMName
	switch mode {
	case "quarantine", "nat":
		if err := s.VBox.ModifyVM(vm, "nic1", "nat"); err != nil {
			return err
		}
		if err := s.EnsureAgentPortForward(); err != nil {
			return fmt.Errorf("agent NAT port forward: %w", err)
		}
	case "offline", "none":
		if err := s.VBox.ModifyVM(vm, "nic1", "none"); err != nil {
			return err
		}
		_ = s.RemoveAgentPortForward()
	case "intnet":
		if err := s.VBox.ModifyVM(vm, "nic1", "intnet"); err != nil {
			return err
		}
		if s.Cfg.Network.IntnetName != "" {
			if err := s.VBox.ModifyVM(vm, "intnet1", s.Cfg.Network.IntnetName); err != nil {
				return err
			}
		}
	case "hostonly":
		if err := s.VBox.ModifyVM(vm, "nic1", "hostonly"); err != nil {
			return err
		}
		if s.Cfg.Network.HostOnlyAdapter != "" {
			if err := s.VBox.ModifyVM(vm, "hostonlyadapter1", s.Cfg.Network.HostOnlyAdapter); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unknown network mode: %s", mode)
	}
	s.Cfg.Network.Mode = mode
	return nil
}

// SetClipboard sets clipboard mode.
func (s *Service) SetClipboard(mode string) error {
	return s.VBox.ModifyVM(s.Cfg.VMName, "clipboard-mode", mode)
}
