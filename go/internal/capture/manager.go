package capture

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/vbox"
)

// GatewayCapture controls tcpdump on the Linux gateway VM.
type GatewayCapture interface {
	StartCapture() (string, error)
	StopCapture() (string, error)
	Status() string
}

// Manager runs host packet capture (VirtualBox NIC trace, gateway tcpdump, or legacy tshark).
type Manager struct {
	Cfg     *config.Config
	VBox    *vbox.Client
	Gateway GatewayCapture
	mu      sync.Mutex

	nicCheckedAt time.Time
	nicCachedOn  bool
}

type captureState struct {
	PID       int    `json:"pid"`
	PcapPath  string `json:"pcapPath"`
	Interface string `json:"interface,omitempty"`
	Filter    string `json:"filter,omitempty"`
	GuestIP   string `json:"guestIp,omitempty"`
	Mode      string `json:"mode,omitempty"`
	StartedAt string `json:"startedAt,omitempty"`
}

// New creates capture manager.
func New(cfg *config.Config, vb *vbox.Client) *Manager {
	return &Manager{Cfg: cfg, VBox: vb}
}

func (m *Manager) logDir() string {
	dir := strings.TrimSpace(m.Cfg.Network.Capture.LogDir)
	if dir == "" {
		dir = filepath.Join(m.Cfg.DataDir(), "logs", "pcap")
	}
	return dir
}

func (m *Manager) statePath() string {
	return filepath.Join(m.logDir(), "capture.state.json")
}

func (m *Manager) mode() string {
	if m.Cfg.IsGatewayMode() {
		return "gateway"
	}
	mode := strings.ToLower(strings.TrimSpace(m.Cfg.Network.Capture.Mode))
	if mode == "" {
		return "guest-nic"
	}
	return mode
}

func (m *Manager) readState() captureState {
	raw, err := os.ReadFile(m.statePath())
	if err != nil {
		return captureState{}
	}
	var st captureState
	_ = json.Unmarshal(raw, &st)
	return st
}

func (m *Manager) writeState(st captureState) error {
	if err := os.MkdirAll(m.logDir(), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.statePath(), raw, 0o644)
}

func (m *Manager) clearState() {
	_ = os.Remove(m.statePath())
}

// StatusInfo is structured capture status for CLI/UI.
type StatusInfo struct {
	Running   bool   `json:"running"`
	Mode      string `json:"mode"`
	PcapPath  string `json:"pcapPath"`
	StartedAt string `json:"startedAt"`
	Message   string `json:"message"`
	Stale     bool   `json:"stale"`
	Enabled   bool   `json:"enabled"`
}

func (m *Manager) nicTraceActive(force bool) bool {
	if m.VBox == nil {
		return false
	}
	if !force && !m.nicCheckedAt.IsZero() && time.Since(m.nicCheckedAt) < 15*time.Second {
		return m.nicCachedOn
	}
	out, err := m.VBox.RunWithTimeout(30*time.Second, "showvminfo", m.Cfg.VMName)
	active := err == nil && strings.Contains(strings.ToLower(out), "trace: on")
	m.nicCheckedAt = time.Now()
	m.nicCachedOn = active
	return active
}

// Info returns capture status, clearing stale state when VBox nictrace is off.
func (m *Manager) Info() StatusInfo {
	m.mu.Lock()
	defer m.mu.Unlock()

	info := StatusInfo{
		Enabled: m.Cfg.Network.Capture.Enabled,
		Mode:    m.mode(),
	}
	if !info.Enabled {
		info.Message = "capture disabled in config"
		return info
	}

	st := m.readState()
	info.PcapPath = st.PcapPath
	info.StartedAt = st.StartedAt
	if st.Mode != "" {
		info.Mode = st.Mode
	}

	if st.Mode == "gateway" || m.mode() == "gateway" {
		if st.PcapPath != "" && st.StartedAt != "" {
			info.Running = true
			info.Message = "running — gateway " + filepath.Base(st.PcapPath)
			return info
		}
		info.Message = "stopped"
		return info
	}

	if st.PcapPath == "" && st.PID == 0 {
		info.Message = "stopped"
		return info
	}

	if st.Mode == "guest-nic" || st.Mode == "vbox-nictrace" || st.Mode == "" {
		if m.nicTraceActive(false) {
			info.Running = true
			info.Message = "running"
			if st.PcapPath != "" {
				info.Message = "running — " + filepath.Base(st.PcapPath)
			}
			return info
		}
		info.Stale = true
		info.Running = false
		info.Message = "stopped (stale session cleared)"
		if st.PcapPath != "" {
			info.Message = "stopped — last PCAP " + filepath.Base(st.PcapPath)
		}
		m.clearState()
		info.PcapPath = st.PcapPath
		return info
	}

	if st.PID > 0 {
		if p, err := os.FindProcess(st.PID); err == nil {
			_ = p
			info.Running = true
			info.Message = fmt.Sprintf("running (pid %d)", st.PID)
			return info
		}
	}
	info.Message = "stopped"
	m.clearState()
	return info
}

// Start begins packet capture.
func (m *Manager) Start() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.Cfg.Network.Capture.Enabled {
		return "", fmt.Errorf("capture disabled in config")
	}

	st := m.readState()
	mode := m.mode()
	if st.PcapPath != "" {
		same := st.Mode == mode ||
			((mode == "guest-nic" || mode == "vbox-nictrace") && (st.Mode == "guest-nic" || st.Mode == "vbox-nictrace"))
		if same && mode == "gateway" {
			fmt.Printf("Capture already running (gateway).\n  PCAP: %s\n", st.PcapPath)
			return st.PcapPath, nil
		}
		if same && (st.Mode == "guest-nic" || st.Mode == "vbox-nictrace") {
			if m.nicTraceActive(true) {
				fmt.Printf("Capture already running (VirtualBox NIC trace).\n  PCAP: %s\n", st.PcapPath)
				return st.PcapPath, nil
			}
			m.clearState()
			st = captureState{}
		} else if !same {
			fmt.Printf("Stopping previous capture (mode=%s) before starting %s...\n", st.Mode, mode)
			if st.Mode == "gateway" && m.Gateway != nil {
				_, _ = m.Gateway.StopCapture()
			} else if st.Mode == "guest-nic" || st.Mode == "vbox-nictrace" {
				if m.VBox != nil {
					_, _ = m.VBox.RunWithTimeout(time.Minute, "controlvm", m.Cfg.VMName, "nictrace1", "off")
				}
			} else if st.PID > 0 {
				if p, err := os.FindProcess(st.PID); err == nil {
					_ = p.Kill()
				}
			}
			m.clearState()
		}
	}

	if mode == "gateway" {
		if m.Gateway == nil {
			return "", fmt.Errorf("gateway capture requires gateway manager")
		}
		path, err := m.Gateway.StartCapture()
		if err != nil {
			return "", err
		}
		if path == "" {
			path = "gateway:/var/log/quarantine/pcap"
		}
		st = captureState{
			PcapPath:  path,
			Interface: "gateway-lan",
			Filter:    "all LAN frames via gateway tcpdump",
			GuestIP:   m.Cfg.Network.Gateway.WithDefaults(m.Cfg.Network.IntnetName).GuestIP,
			Mode:      "gateway",
			StartedAt: time.Now().Format(time.RFC3339),
		}
		if err := m.writeState(st); err != nil {
			return "", err
		}
		fmt.Printf("Packet capture started (gateway tcpdump).\n  PCAP: %s\n", path)
		return path, nil
	}

	if err := os.MkdirAll(m.logDir(), 0o755); err != nil {
		return "", err
	}
	pcapPath := filepath.Join(m.logDir(), fmt.Sprintf("quarantine-%s.pcap", time.Now().Format("20060102-150405")))
	guestIP := m.Cfg.Network.Capture.GuestIP
	if guestIP == "" {
		guestIP = "10.0.2.15"
	}

	if mode == "guest-nic" || mode == "vbox-nictrace" {
		if m.VBox == nil {
			return "", fmt.Errorf("VBoxManage client required for guest-nic capture")
		}
		state, err := m.VBox.VMState(m.Cfg.VMName)
		if err != nil {
			return "", err
		}
		if !strings.EqualFold(state, "running") {
			return "", fmt.Errorf("VM %q is not running (state=%s); start it before guest-nic capture", m.Cfg.VMName, state)
		}
		if _, err := m.VBox.RunWithTimeout(time.Minute, "controlvm", m.Cfg.VMName, "nictracefile1", pcapPath); err != nil {
			return "", fmt.Errorf("nictracefile1: %w", err)
		}
		if _, err := m.VBox.RunWithTimeout(time.Minute, "controlvm", m.Cfg.VMName, "nictrace1", "on"); err != nil {
			return "", fmt.Errorf("nictrace1 on: %w", err)
		}
		m.nicCheckedAt = time.Now()
		m.nicCachedOn = true
		st = captureState{
			PID:       0,
			PcapPath:  pcapPath,
			Interface: "vbox-nic1",
			Filter:    "all guest NIC frames (includes UDP/53 DNS)",
			GuestIP:   guestIP,
			Mode:      "guest-nic",
			StartedAt: time.Now().Format(time.RFC3339),
		}
		if err := m.writeState(st); err != nil {
			return "", err
		}
		fmt.Printf("Packet capture started (VirtualBox NIC trace).\n  PCAP: %s\n", pcapPath)
		return pcapPath, nil
	}

	return "", fmt.Errorf("capture mode %q not supported in Go CLI; use guest-nic or gateway", mode)
}

// Stop stops capture.
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	st := m.readState()
	if st.Mode == "gateway" || m.mode() == "gateway" {
		var syncMsg string
		if m.Gateway != nil {
			msg, err := m.Gateway.StopCapture()
			syncMsg = msg
			if err != nil {
				fmt.Printf("Gateway capture stop warning: %v\n", err)
			}
		}
		if st.PcapPath != "" {
			fmt.Printf("PCAP (gateway): %s\n", st.PcapPath)
		}
		if syncMsg != "" {
			fmt.Println(syncMsg)
		}
		m.clearState()
		return nil
	}

	active := m.nicTraceActive(true)
	if st.PcapPath == "" && st.PID == 0 && !active {
		fmt.Println("No capture session found.")
		return nil
	}
	if st.Mode == "guest-nic" || st.Mode == "vbox-nictrace" || st.Mode == "" || active {
		if m.VBox != nil {
			_, _ = m.VBox.RunWithTimeout(time.Minute, "controlvm", m.Cfg.VMName, "nictrace1", "off")
		}
	} else if st.PID > 0 {
		if p, err := os.FindProcess(st.PID); err == nil {
			_ = p.Kill()
		}
	}
	if st.PcapPath != "" {
		fmt.Printf("PCAP saved: %s\n", st.PcapPath)
	} else {
		fmt.Println("Capture stopped.")
	}
	m.nicCheckedAt = time.Now()
	m.nicCachedOn = false
	m.clearState()
	return nil
}

// Status returns a short human-readable state (verifies VBox nictrace).
func (m *Manager) Status() string {
	info := m.Info()
	if info.Running {
		if info.PcapPath != "" {
			return fmt.Sprintf("running (%s, %s)", info.Mode, info.PcapPath)
		}
		return "running"
	}
	if info.Message != "" {
		return info.Message
	}
	return "stopped"
}
