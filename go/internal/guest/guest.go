package guest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quarantine-lab/quarantine/internal/agent/guestpaths"
	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/vbox"
)

// Client runs operations in the Windows guest via agent or guestcontrol.
type Client struct {
	Cfg  *config.Config
	VBox *vbox.Client
	tr   Transport
}

// New creates a guest client.
func New(cfg *config.Config, vb *vbox.Client) *Client {
	return &Client{Cfg: cfg, VBox: vb}
}

func (c *Client) Transport() Transport {
	if c.tr == nil {
		c.tr = NewTransport(c.Cfg, c.VBox)
	}
	return c.tr
}

// SetTransport overrides the host↔guest transport (tests).
func (c *Client) SetTransport(t Transport) {
	c.tr = t
}

// Credentials for an account block (guestcontrol fallback).
type Credentials struct {
	Username string
	Password string
	Domain   string
}

// GuestCreds returns admin lab credentials.
func (c *Client) GuestCreds() Credentials {
	return Credentials{
		Username: c.Cfg.Guest.Username,
		Password: c.Cfg.Guest.Password,
		Domain:   c.Cfg.Guest.Domain,
	}
}

// PayloadCreds returns payload user credentials.
func (c *Client) PayloadCreds() Credentials {
	return Credentials{
		Username: c.Cfg.Payload.Username,
		Password: c.Cfg.Payload.Password,
		Domain:   c.Cfg.Payload.Domain,
	}
}

func (c *Client) timeout(account AccountConfig) time.Duration {
	ms := account.TimeoutMs
	if ms <= 0 {
		ms = 120000
	}
	return time.Duration(ms) * time.Millisecond
}

type AccountConfig = config.AccountConfig

func (c *Client) ctxTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		d = 120 * time.Second
	}
	return context.WithTimeout(context.Background(), d)
}

// RunPowerShell runs a script in the guest as the lab admin (or SYSTEM via agent).
func (c *Client) RunPowerShell(scriptPath string, args []string, creds Credentials) (string, error) {
	psArgs := append([]string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", scriptPath}, args...)
	ctx, cancel := c.ctxTimeout(c.timeout(c.Cfg.Guest))
	defer cancel()
	account := UserSystem
	if c.Cfg.UseGuestAdditions() {
		account = UserGuest
	}
	return c.Transport().Run(ctx, account, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, psArgs, c.timeout(c.Cfg.Guest))
}

// Run executes a program in the guest as system, guest, or payload.
func (c *Client) Run(account, exe string, args []string, timeout time.Duration) (string, error) {
	ctx, cancel := c.ctxTimeout(timeout)
	defer cancel()
	return c.Transport().Run(ctx, account, exe, args, timeout)
}

// CopyTo copies a host file into a guest directory (basename preserved).
func (c *Client) CopyTo(hostPath, guestDir string, creds Credentials) error {
	abs, err := filepath.Abs(hostPath)
	if err != nil {
		return err
	}
	guestDest := guestpaths.GuestJoin(guestDir, filepath.Base(abs))
	ctx, cancel := c.ctxTimeout(c.timeout(c.Cfg.Guest))
	defer cancel()
	_ = c.Transport().Mkdir(ctx, guestDir)
	return c.Transport().CopyTo(ctx, abs, guestDest)
}

func (c *Client) CopyToDest(hostPath, guestDest string) error {
	ctx, cancel := c.ctxTimeout(c.timeout(c.Cfg.Guest))
	defer cancel()
	parent := filepath.Dir(guestDest)
	_ = c.Transport().Mkdir(ctx, parent)
	return c.Transport().CopyTo(ctx, hostPath, guestDest)
}

// CopyFrom copies a guest file to a host path.
func (c *Client) CopyFrom(guestPath, hostPath string, creds Credentials) error {
	ctx, cancel := c.ctxTimeout(c.timeout(c.Cfg.Guest))
	defer cancel()
	return c.Transport().CopyFrom(ctx, guestPath, hostPath)
}

func (c *Client) Remove(guestPath string) error {
	ctx, cancel := c.ctxTimeout(30 * time.Second)
	defer cancel()
	return c.Transport().Remove(ctx, guestPath)
}

func (c *Client) Ready() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return c.Transport().Ready(ctx)
}

// DeployScript copies a host script to guest copyTargetDir.
func (c *Client) DeployScript(hostScriptPath string, creds Credentials) (string, error) {
	dir := c.Cfg.Guest.CopyTargetDir
	if dir == "" {
		dir = `C:\Users\Public\Quarantine`
	}
	if err := c.CopyTo(hostScriptPath, dir, creds); err != nil {
		return "", err
	}
	return filepath.Join(dir, filepath.Base(hostScriptPath)), nil
}

// DeployGatewaySetup copies gateway commission scripts + CA into the lab guest.
func (c *Client) DeployGatewaySetup(projectRoot string) (string, error) {
	creds := c.GuestCreds()
	dir := c.Cfg.Guest.CopyTargetDir
	if dir == "" {
		dir = `C:\Users\Public\Quarantine`
	}
	files := []string{
		filepath.Join(projectRoot, "network", "guest", "Configure-QuarantineGuestNetwork.ps1"),
		filepath.Join(projectRoot, "network", "guest", "Harden-QuarantineGuestNetwork.ps1"),
		filepath.Join(projectRoot, "network", "guest", "Install-QuarantineProxyCA.ps1"),
		filepath.Join(projectRoot, "network", "proxy", "mitmproxy-ca-cert.cer"),
	}
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			return "", fmt.Errorf("missing %s (run gateway export-ca if the .cer is absent): %w", f, err)
		}
		if err := c.CopyTo(f, dir, creds); err != nil {
			return "", fmt.Errorf("copy %s: %w", filepath.Base(f), err)
		}
	}
	return fmt.Sprintf(`Gateway setup files copied to %s

  Configure-QuarantineGuestNetwork.ps1
  Harden-QuarantineGuestNetwork.ps1
  Install-QuarantineProxyCA.ps1
  mitmproxy-ca-cert.cer

In the guest (elevated PowerShell):

  powershell -ExecutionPolicy Bypass -File %s\Configure-QuarantineGuestNetwork.ps1 -Mode gateway

Or gap-fix only:

  powershell -ExecutionPolicy Bypass -File %s\Harden-QuarantineGuestNetwork.ps1 -Mode gateway

If SSL warnings remain:

  powershell -ExecutionPolicy Bypass -File %s\Install-QuarantineProxyCA.ps1 -ProxyHost 10.66.0.1 -ProxyPort 8080 -PacPort 8080 -CaPath %s\mitmproxy-ca-cert.cer

Host reaches the agent only via the Linux gateway: 127.0.0.1:9443 → gateway → lab 10.66.0.15:9443 (no lab NAT NIC).

Prefer a full first-boot in the guest:
  powershell -ExecutionPolicy Bypass -File %s\Invoke-QuarantineGuestProvision.ps1
`, dir, dir, dir, dir, dir, dir), nil
}

func (c *Client) publicDir() string {
	dir := c.Cfg.Guest.CopyTargetDir
	if dir == "" {
		return `C:\Users\Public\Quarantine`
	}
	return dir
}

func resolveProjectFile(root, p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(root, filepath.FromSlash(p))
}

func (c *Client) copyOptional(hostPath, destDir string, creds Credentials) (string, error) {
	if _, err := os.Stat(hostPath); err != nil {
		return "", nil
	}
	if err := c.CopyTo(hostPath, destDir, creds); err != nil {
		return "", fmt.Errorf("copy %s: %w", filepath.Base(hostPath), err)
	}
	return filepath.Base(hostPath), nil
}

// DeployProvisionFiles copies every elevated guest helper used on a new lab VM.
func (c *Client) DeployProvisionFiles(projectRoot string) (copied []string, skipped []string, err error) {
	creds := c.GuestCreds()
	dir := c.publicDir()
	optional := []string{
		filepath.Join(projectRoot, "guest", "Invoke-QuarantineGuestProvision.ps1"),
		filepath.Join(projectRoot, "manifest", "Install-QuarantineAgent.ps1"),
		filepath.Join(projectRoot, "guest", "Grant-QuarantineGuestEventLogAccess.ps1"),
		filepath.Join(projectRoot, "guest", "Invoke-QuarantineGuestElevated.ps1"),
		filepath.Join(projectRoot, "guest", "Export-QuarantineAgentToken.ps1"),
		filepath.Join(projectRoot, "network", "guest", "Configure-QuarantineGuestNetwork.ps1"),
		filepath.Join(projectRoot, "network", "guest", "Harden-QuarantineGuestNetwork.ps1"),
		filepath.Join(projectRoot, "network", "guest", "Install-QuarantineProxyCA.ps1"),
		filepath.Join(projectRoot, "network", "guest", "Disable-QuarantineAutoLogon.ps1"),
		filepath.Join(projectRoot, "network", "guest", "Disable-QuarantineGuestUpdates.ps1"),
		filepath.Join(projectRoot, "network", "proxy", "mitmproxy-ca-cert.cer"),
	}
	for _, f := range optional {
		name, cErr := c.copyOptional(f, dir, creds)
		if cErr != nil {
			return copied, skipped, cErr
		}
		if name == "" {
			skipped = append(skipped, filepath.Base(f))
			continue
		}
		copied = append(copied, name)
	}

	hints, hErr := json.MarshalIndent(map[string]string{
		"payloadUser": c.Cfg.Payload.Username,
		"labAdmin":    c.Cfg.Guest.Username,
		"networkMode": "gateway",
	}, "", "  ")
	if hErr != nil {
		return copied, skipped, hErr
	}
	tmpHints := filepath.Join(os.TempDir(), "guest-provision.json")
	if err := os.WriteFile(tmpHints, append(hints, '\n'), 0o600); err != nil {
		return copied, skipped, err
	}
	defer os.Remove(tmpHints)
	if err := c.CopyTo(tmpHints, dir, creds); err != nil {
		return copied, skipped, fmt.Errorf("copy guest-provision.json: %w", err)
	}
	copied = append(copied, "guest-provision.json")

	sysmonDir := strings.TrimSpace(c.Cfg.Sysmon.GuestDir)
	if sysmonDir == "" {
		sysmonDir = dir + `\sysmon`
	}
	sysmonName := strings.TrimSpace(c.Cfg.Sysmon.GuestConfigName)
	if sysmonName == "" {
		sysmonName = "quarantine-lab.xml"
	}
	sysmonFiles := []string{
		filepath.Join(projectRoot, "guest", "Install-QuarantineSysmon.ps1"),
		resolveProjectFile(projectRoot, c.Cfg.Sysmon.HostConfigPath),
		filepath.Join(projectRoot, "config", "sysmon", "quarantine-lab.xml"),
		filepath.Join(projectRoot, "config", "sysmon", "quarantine-lab-fallback.xml"),
		resolveProjectFile(projectRoot, c.Cfg.Sysmon.HostSysmonExe),
		filepath.Join(projectRoot, "tools", "Sysmon64.exe"),
	}
	seenSysmon := map[string]bool{}
	for _, f := range sysmonFiles {
		if f == "" {
			continue
		}
		base := filepath.Base(f)
		if seenSysmon[base] {
			continue
		}
		if _, err := os.Stat(f); err != nil {
			if strings.EqualFold(base, "Sysmon64.exe") || strings.EqualFold(base, sysmonName) || strings.EqualFold(base, "Install-QuarantineSysmon.ps1") {
				skipped = append(skipped, "sysmon/"+base)
			}
			continue
		}
		if err := c.CopyTo(f, sysmonDir, creds); err != nil {
			return copied, skipped, fmt.Errorf("copy sysmon %s: %w", base, err)
		}
		seenSysmon[base] = true
		copied = append(copied, "sysmon/"+base)
	}
	return copied, skipped, nil
}

// TestGuestSession verifies the selected transport is reachable.
func (c *Client) TestGuestSession(creds Credentials) error {
	if err := c.Ready(); err != nil {
		return fmt.Errorf("guest session test failed: %w", err)
	}
	return nil
}
