package guest

import (
	"fmt"
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
	guestDest := filepath.Join(guestDir, filepath.Base(hostPath))
	return c.VBox.GuestControlCopyTo(
		c.Cfg.VMName, creds.Username, creds.Password,
		hostPath, guestDest, c.timeout(c.Cfg.Guest),
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
