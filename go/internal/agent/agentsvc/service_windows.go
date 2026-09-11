//go:build windows

package agentsvc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/quarantine-lab/quarantine/internal/agent/guestpaths"
	"github.com/quarantine-lab/quarantine/internal/agent/server"
	"github.com/quarantine-lab/quarantine/internal/agent/types"
	"github.com/quarantine-lab/quarantine/internal/agent/winacl"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	ServiceName = "QuarantineLabAgent"
	DisplayName = "Quarantine Lab Agent"

	win32ErrorServiceMarkedForDeletion = 1072
)

// RunConsole runs the HTTP server in foreground (debug).
func RunConsole(token string, cfg types.AgentConfig) error {
	srv := server.New(token, cfg)
	return srv.ListenAndServe()
}

// RunService runs as Windows service.
func RunService(token string, cfg types.AgentConfig) error {
	elog, err := eventlog.Open(ServiceName)
	if err != nil {
		return RunDebugService(ServiceName, token, cfg)
	}
	handler := &serviceHandler{token: token, cfg: cfg, elog: elog}
	return svc.Run(ServiceName, handler)
}

type serviceHandler struct {
	token string
	cfg   types.AgentConfig
	elog  debug.Log
	srv   *server.Server
}

func (h *serviceHandler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	h.srv = server.New(h.token, h.cfg)
	go func() {
		if err := h.srv.ListenAndServe(); err != nil {
			_ = h.elog.Error(1, fmt.Sprintf("agent server: %v", err))
			_ = appendAgentLog(fmt.Sprintf("server error: %v", err))
		}
	}()

	// Brief pause so ListenAndServe binds before SCM reports running.
	time.Sleep(300 * time.Millisecond)

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	_ = h.elog.Info(1, "Quarantine Lab Agent started")

	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = h.srv.Shutdown(ctx)
			cancel()
			changes <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
	return false, 0
}

// Install registers the Windows service.
func Install(exePath, token string, cfg types.AgentConfig) error {
	if exePath == "" {
		var err error
		exePath, err = os.Executable()
		if err != nil {
			return err
		}
	}
	if cfg.TokenFile == "" {
		cfg.TokenFile = DefaultTokenPath()
	}
	winacl.RememberGuestControlUser()
	if dir := filepath.Dir(exePath); guestpaths.IsProtectedRoot(dir) {
		if err := winacl.Protect(dir); err != nil {
			return fmt.Errorf("protect install dir: %w", err)
		}
	}
	if err := SaveConfig(cfg); err != nil {
		return err
	}
	if err := SaveToken(token, cfg.TokenFile); err != nil {
		return err
	}
	_ = eventlog.InstallAsEventCreate(ServiceName, eventlog.Info|eventlog.Warning|eventlog.Error)
	ensureFirewallRule(cfg.Port)

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	if err := removeExistingService(m); err != nil {
		return err
	}
	s, err := createServiceWithRetry(m, exePath)
	if err != nil {
		if errno, ok := err.(windows.Errno); ok && errno == windows.ERROR_ACCESS_DENIED {
			return fmt.Errorf("%w — open PowerShell as Administrator in the guest VM and run: \"%s\" install -token=...", err, exePath)
		}
		return err
	}
	defer s.Close()
	if err := s.Start(); err != nil {
		return err
	}
	_ = appendAgentLog("service started")
	return nil
}

// Uninstall removes the service.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	return removeExistingService(m)
}

func removeExistingService(m *mgr.Mgr) error {
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return nil
	}
	defer s.Close()

	if status, qErr := s.Query(); qErr == nil && status.State != svc.Stopped {
		_, _ = s.Control(svc.Stop)
		_ = waitForServiceState(s, svc.Stopped, 30*time.Second)
	}
	if err := s.Delete(); err != nil {
		return err
	}
	return waitForServiceRemoved(m, 45*time.Second)
}

func createServiceWithRetry(m *mgr.Mgr, exePath string) (*mgr.Service, error) {
	cfg := mgr.Config{
		DisplayName: DisplayName,
		Description: "Quarantine lab evidence collector (USN, Sysmon, registry)",
		StartType:   mgr.StartAutomatic,
	}
	var lastErr error
	for attempt := 0; attempt < 60; attempt++ {
		s, err := m.CreateService(ServiceName, exePath, cfg, "run")
		if err == nil {
			return s, nil
		}
		lastErr = err
		if errno, ok := err.(windows.Errno); ok && errno == win32ErrorServiceMarkedForDeletion {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		return nil, err
	}
	return nil, fmt.Errorf("%w — close services.msc if open, wait 30s, or reboot the VM", lastErr)
}

func waitForServiceState(s *mgr.Service, want svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status, err := s.Query()
		if err != nil {
			return err
		}
		if status.State == want {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("service did not reach state %d within %v", want, timeout)
}

func waitForServiceRemoved(m *mgr.Mgr, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s, err := m.OpenService(ServiceName)
		if err != nil {
			return nil
		}
		_ = s.Close()
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("service %q still deleting after %v — close services.msc or reboot the VM", ServiceName, timeout)
}

// ConfigDir is SYSTEM/Administrators-only ProgramData (not Users\Public).
func ConfigDir() string {
	return guestpaths.DataDir
}

func ConfigPath() string {
	return guestpaths.ConfigPath()
}

func DefaultTokenPath() string {
	return guestpaths.TokenPath()
}

func SaveConfig(cfg types.AgentConfig) error {
	if err := winacl.Protect(ConfigDir()); err != nil {
		if mkErr := os.MkdirAll(ConfigDir(), 0o700); mkErr != nil {
			return mkErr
		}
		if err := winacl.Protect(ConfigDir()); err != nil {
			return fmt.Errorf("protect agent data dir: %w", err)
		}
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(ConfigPath(), raw, 0o600); err != nil {
		return err
	}
	return winacl.Protect(ConfigPath())
}

func LoadConfig() (types.AgentConfig, error) {
	cfg := types.AgentConfig{Port: 9443, TokenFile: DefaultTokenPath()}
	raw, err := os.ReadFile(ConfigPath())
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func SaveToken(token, path string) error {
	if path == "" {
		path = DefaultTokenPath()
	}
	if err := winacl.Protect(filepath.Dir(path)); err != nil {
		if mkErr := os.MkdirAll(filepath.Dir(path), 0o700); mkErr != nil {
			return mkErr
		}
		_ = winacl.Protect(filepath.Dir(path))
	}
	if err := os.WriteFile(path, []byte(strings.TrimSpace(token)+"\n"), 0o600); err != nil {
		return err
	}
	return winacl.Protect(path)
}

func LoadToken(path string) (string, error) {
	if path == "" {
		path = DefaultTokenPath()
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func IsWindowsService() (bool, error) {
	return svc.IsWindowsService()
}

func RunDebugService(name string, token string, cfg types.AgentConfig) error {
	elog := debug.New(name)
	handler := &serviceHandler{token: token, cfg: cfg, elog: elog}
	return svc.Run(name, handler)
}

func ensureFirewallRule(port int) {
	if port <= 0 {
		port = 9443
	}
	name := "Quarantine Lab Agent"
	_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name).Run()
	_ = exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+name,
		"dir=in",
		"action=allow",
		"protocol=TCP",
		fmt.Sprintf("localport=%d", port),
		"profile=any",
		"enable=yes",
	).Run()
}

func appendAgentLog(msg string) error {
	path := guestpaths.LogPath()
	_ = winacl.Protect(filepath.Dir(path))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s %s\n", time.Now().UTC().Format(time.RFC3339), msg)
	return err
}
