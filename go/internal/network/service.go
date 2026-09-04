package network

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/vbox"
)

// GatewayEnabler starts the Linux gateway and attaches the lab guest.
type GatewayEnabler interface {
	EnableMode() error
}

// Service manages VM network modes.
type Service struct {
	Cfg     *config.Config
	VBox    *vbox.Client
	Gateway GatewayEnabler
	CfgPath string
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
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "offline" {
		mode = "intnet"
	}
	vm := s.Cfg.VMName
	switch mode {
	case "gateway":
		if s.Gateway == nil {
			return fmt.Errorf("gateway mode requires gateway manager (create/provision gateway first)")
		}
		if err := s.Gateway.EnableMode(); err != nil {
			return err
		}
		g := s.Cfg.Network.Gateway.WithDefaults(s.Cfg.Network.IntnetName)
		s.Cfg.Network.Mode = "gateway"
		s.Cfg.Network.GuestGateway = g.LANGateway
		s.Cfg.Network.GuestDNS = g.LANGateway
		s.Cfg.Network.Capture.GuestIP = g.GuestIP
		if strings.TrimSpace(s.Cfg.Network.Capture.Mode) == "" || s.Cfg.Network.Capture.Mode == "guest-nic" {
			s.Cfg.Network.Capture.Mode = "gateway"
		}
		_ = s.persistNetworkMode("gateway")
		return nil
	case "quarantine", "nat":
		if err := s.VBox.ModifyVM(vm, "nic1", "nat"); err != nil {
			return err
		}
		if err := s.EnsureAgentPortForward(); err != nil {
			return fmt.Errorf("agent NAT port forward: %w", err)
		}
	case "none":
		if err := s.VBox.ModifyVM(vm, "nic1", "none"); err != nil {
			return err
		}
		_ = s.RemoveAgentPortForward()
	case "intnet":
		if err := s.VBox.ModifyVM(vm, "nic1", "intnet"); err != nil {
			return err
		}
		intnet := s.Cfg.Network.IntnetName
		if intnet == "" {
			intnet = "quarantine-net"
		}
		if err := s.VBox.ModifyVM(vm, "intnet1", intnet); err != nil {
			return err
		}
		_ = s.RemoveAgentPortForward()
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
	_ = s.persistNetworkMode(mode)
	return nil
}

func (s *Service) persistNetworkMode(mode string) error {
	if strings.TrimSpace(s.CfgPath) == "" {
		return nil
	}
	raw, err := os.ReadFile(s.CfgPath)
	if err != nil {
		return err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	netObj, _ := doc["network"].(map[string]any)
	if netObj == nil {
		netObj = map[string]any{}
		doc["network"] = netObj
	}
	netObj["mode"] = mode
	if mode == "gateway" {
		g := s.Cfg.Network.Gateway.WithDefaults(s.Cfg.Network.IntnetName)
		netObj["guestGateway"] = g.LANGateway
		netObj["guestDns"] = g.LANGateway
		if capObj, ok := netObj["capture"].(map[string]any); ok {
			capObj["guestIp"] = g.GuestIP
			capObj["mode"] = "gateway"
		}
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.CfgPath, append(out, '\n'), 0o644)
}

// SetClipboard sets clipboard mode.
func (s *Service) SetClipboard(mode string) error {
	return s.VBox.ModifyVM(s.Cfg.VMName, "clipboard-mode", mode)
}
