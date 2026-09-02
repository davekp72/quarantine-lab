package capture

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/quarantine-lab/quarantine/internal/config"
)

// Manager runs tshark PCAP capture.
type Manager struct {
	Cfg  *config.Config
	cmd  *exec.Cmd
	mu   sync.Mutex
	file string
}

// New creates capture manager.
func New(cfg *config.Config) *Manager {
	return &Manager{Cfg: cfg}
}

// Start begins PCAP capture to logDir.
func (m *Manager) Start() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd != nil && m.cmd.Process != nil {
		return m.file, nil
	}
	tshark, err := exec.LookPath("tshark")
	if err != nil {
		return "", fmt.Errorf("tshark not found in PATH")
	}
	logDir := m.Cfg.Network.Capture.LogDir
	if logDir == "" {
		logDir = filepath.Join(m.Cfg.DataDir(), "logs", "pcap")
	}
	_ = os.MkdirAll(logDir, 0o755)
	m.file = filepath.Join(logDir, fmt.Sprintf("capture-%s.pcapng", time.Now().Format("20060102-150405")))
	iface := m.Cfg.Network.Capture.Interface
	if iface == "" {
		iface = "1"
	}
	m.cmd = exec.Command(tshark, "-i", iface, "-w", m.file)
	m.cmd.Stdout = os.Stdout
	m.cmd.Stderr = os.Stderr
	if err := m.cmd.Start(); err != nil {
		return "", err
	}
	return m.file, nil
}

// Stop stops capture.
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd == nil || m.cmd.Process == nil {
		return nil
	}
	err := m.cmd.Process.Kill()
	m.cmd = nil
	return err
}

// Status returns state.
func (m *Manager) Status() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd != nil && m.cmd.Process != nil {
		return "running"
	}
	return "stopped"
}
