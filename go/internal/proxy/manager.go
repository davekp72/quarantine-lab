package proxy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/quarantine-lab/quarantine/internal/config"
)

// Manager runs mitmproxy subprocess.
type Manager struct {
	Cfg    *config.Config
	cmd    *exec.Cmd
	mu     sync.Mutex
	Root   string
}

// New creates proxy manager.
func New(cfg *config.Config, projectRoot string) *Manager {
	return &Manager{Cfg: cfg, Root: projectRoot}
}

func (m *Manager) mitmdumpPath() (string, error) {
	venv := filepath.Join(m.Root, ".venv", "Scripts", "mitmdump.exe")
	if _, err := os.Stat(venv); err == nil {
		return venv, nil
	}
	p, err := exec.LookPath("mitmdump")
	if err != nil {
		return "", fmt.Errorf("mitmdump not found; run Setup-Dependencies.ps1")
	}
	return p, nil
}

// Start launches mitmdump with block script.
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd != nil && m.cmd.Process != nil {
		return nil
	}
	bin, err := m.mitmdumpPath()
	if err != nil {
		return err
	}
	script := filepath.Join(m.Root, "network", "proxy", "block_private.py")
	args := []string{
		"-p", fmt.Sprintf("%d", m.Cfg.Network.Proxy.ListenPort),
		"--set", "block_global=false",
	}
	if _, err := os.Stat(script); err == nil {
		args = append(args, "-s", script)
	}
	m.cmd = exec.Command(bin, args...)
	m.cmd.Stdout = os.Stdout
	m.cmd.Stderr = os.Stderr
	if err := m.cmd.Start(); err != nil {
		return err
	}
	return nil
}

// Stop stops mitmdump.
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

// Status returns running state.
func (m *Manager) Status() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd != nil && m.cmd.Process != nil {
		return "running"
	}
	return "stopped"
}
