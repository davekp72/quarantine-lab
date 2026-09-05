package guest

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/vbox"
)

// Client runs guestcontrol operations.
type Client struct {
	Cfg  *config.Config
	VBox *vbox.Client
}

// New creates a guest client.
func New(cfg *config.Config, vb *vbox.Client) *Client {
	return &Client{Cfg: cfg, VBox: vb}
}

// Credentials for an account block.
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

// RunPowerShell runs a script in guest as admin.
func (c *Client) RunPowerShell(scriptPath string, args []string, creds Credentials) (string, error) {
	psArgs := append([]string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", scriptPath}, args...)
	return c.VBox.GuestControlRun(
		c.Cfg.VMName, creds.Username, creds.Password,
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		psArgs, c.timeout(c.Cfg.Guest),
	)
}

// CopyTo copies host file to guest directory.
func (c *Client) CopyTo(hostPath, guestDir string, creds Credentials) error {
	abs, err := filepath.Abs(hostPath)
	if err != nil {
		return err
	}
	guestDest := filepath.Join(guestDir, filepath.Base(abs))
	return c.VBox.GuestControlCopyTo(
		c.Cfg.VMName, creds.Username, creds.Password,
		abs, guestDest, c.timeout(c.Cfg.Guest),
	)
}

// CopyFrom copies guest file to host path.
func (c *Client) CopyFrom(guestPath, hostPath string, creds Credentials) error {
	return c.VBox.GuestControlCopyFrom(
		c.Cfg.VMName, creds.Username, creds.Password,
		guestPath, hostPath, c.timeout(c.Cfg.Guest),
	)
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
		filepath.Join(projectRoot, "network", "guest", "Repair-QuarantineAgentNat.ps1"),
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
  Repair-QuarantineAgentNat.ps1
  Install-QuarantineProxyCA.ps1
  mitmproxy-ca-cert.cer

In the guest (elevated PowerShell):

  powershell -ExecutionPolicy Bypass -File %s\Configure-QuarantineGuestNetwork.ps1 -Mode gateway

If agent health fails (NAT stuck on 169.254.x.x / APIPA):

  powershell -ExecutionPolicy Bypass -File %s\Repair-QuarantineAgentNat.ps1

If SSL warnings remain:

  powershell -ExecutionPolicy Bypass -File %s\Install-QuarantineProxyCA.ps1 -ProxyHost 10.66.0.1 -ProxyPort 8080 -PacPort 8080 -CaPath %s\mitmproxy-ca-cert.cer
`, dir, dir, dir, dir, dir), nil
}

// TestGuestSession verifies guest credentials work.
func (c *Client) TestGuestSession(creds Credentials) error {
	_, err := c.VBox.GuestControlRun(
		c.Cfg.VMName, creds.Username, creds.Password,
		`C:\Windows\System32\cmd.exe`,
		[]string{"/c", "echo", "ok"},
		30*time.Second,
	)
	if err != nil {
		return fmt.Errorf("guest session test failed: %w", err)
	}
	return nil
}
