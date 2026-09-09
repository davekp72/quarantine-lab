package network

import (
	"bytes"
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

// Service manages VM network modes. Sample egress always uses the Linux gateway
// (intnet → Quarantine-Gateway). Host→guest agent reachability is only via
// gateway NAT PF on 127.0.0.1 plus nftables DNAT — never a lab-VM NAT NIC.
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

func (s *Service) agentRuleName() string {
	name := s.Cfg.Agent.NatRuleName
	if name == "" {
		return "quarantine-agent"
	}
	return name
}

func (s *Service) agentPort() int {
	if s.Cfg.Agent.Port > 0 {
		return s.Cfg.Agent.Port
	}
	return 9443
}

func (s *Service) gatewayVM() string {
	return s.Cfg.Network.Gateway.WithDefaults(s.Cfg.Network.IntnetName).VMName
}

// EnsureAgentPortForward publishes the guest agent on host loopback through the Linux gateway:
// 127.0.0.1:port → gateway WAN NAT PF → nftables DNAT → lab 10.66.0.15:port.
func (s *Service) EnsureAgentPortForward() error {
	if !s.Cfg.Agent.Enabled {
		return nil
	}
	name := s.agentRuleName()
	port := s.agentPort()
	gName := s.gatewayVM()
	rule := fmt.Sprintf("%s,tcp,127.0.0.1,%d,,%d", name, port, port)

	// Never leave a lab-VM NAT forward (legacy dual-NIC path).
	_ = s.VBox.NatPFDeleteOn(s.Cfg.VMName, 1, name)
	_ = s.VBox.NatPFDeleteOn(s.Cfg.VMName, 2, name)
	_ = s.VBox.NatPFDeleteOn(gName, 1, name)
	if err := s.VBox.NatPFAddOn(gName, 1, rule); err != nil {
		return fmt.Errorf("gateway NAT port forward: %w", err)
	}
	if af, ok := s.Gateway.(interface{ ApplyAgentLANForward() error }); ok {
		if err := af.ApplyAgentLANForward(); err != nil {
			return fmt.Errorf("gateway LAN DNAT: %w", err)
		}
	}
	return nil
}

// RemoveAgentPortForward deletes agent NAT rules on the lab VM and the Linux gateway.
func (s *Service) RemoveAgentPortForward() error {
	if !s.Cfg.Agent.Enabled {
		return nil
	}
	name := s.agentRuleName()
	_ = s.VBox.NatPFDeleteOn(s.Cfg.VMName, 1, name)
	_ = s.VBox.NatPFDeleteOn(s.Cfg.VMName, 2, name)
	_ = s.VBox.NatPFDeleteOn(s.gatewayVM(), 1, name)
	return nil
}

// SetMode applies network mode. Internet-facing sample analysis always uses "gateway".
// Legacy aliases "quarantine" and "nat" enable gateway mode (host mitmproxy NAT is retired).
func (s *Service) SetMode(mode string) error {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "offline" {
		mode = "intnet"
	}
	if mode == "quarantine" || mode == "nat" {
		mode = "gateway"
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
		if err := s.EnsureAgentPortForward(); err != nil {
			return fmt.Errorf("agent via gateway: %w", err)
		}
		if err := s.persistNetworkMode("gateway"); err != nil {
			return fmt.Errorf("persist network mode: %w", err)
		}
		return nil
	case "none":
		if err := s.VBox.ModifyVM(vm, "nic1", "none"); err != nil {
			return err
		}
		_ = s.VBox.ModifyVM(vm, "nic2", "none")
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
		_ = s.VBox.ModifyVM(vm, "nic2", "none")
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
		_ = s.VBox.ModifyVM(vm, "nic2", "none")
		_ = s.RemoveAgentPortForward()
	default:
		return fmt.Errorf("unknown network mode: %s (use gateway, intnet/offline, none, or hostonly)", mode)
	}
	s.Cfg.Network.Mode = mode
	if err := s.persistNetworkMode(mode); err != nil {
		return fmt.Errorf("persist network mode: %w", err)
	}
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
	raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})
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
