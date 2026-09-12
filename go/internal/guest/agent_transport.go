package guest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quarantine-lab/quarantine/internal/agent/guestpaths"
	"github.com/quarantine-lab/quarantine/internal/agent/types"
	"github.com/quarantine-lab/quarantine/internal/agentclient"
	"github.com/quarantine-lab/quarantine/internal/config"
)

type agentTransport struct {
	cfg *config.Config
}

func newAgentTransport(cfg *config.Config) Transport {
	return &agentTransport{cfg: cfg}
}

func (t *agentTransport) Name() string { return config.TransportAgent }

func (t *agentTransport) client() (*agentclient.Client, error) {
	if t.cfg == nil || !t.cfg.Agent.Enabled {
		return nil, fmt.Errorf("agent is not enabled")
	}
	return agentclient.New(t.cfg)
}

func (t *agentTransport) Ready(ctx context.Context) error {
	c, err := t.client()
	if err != nil {
		return wrapAgentErr(err)
	}
	_, err = c.Health(ctx)
	return wrapAgentErr(err)
}

func (t *agentTransport) Run(ctx context.Context, account, exe string, args []string, timeout time.Duration) (string, error) {
	c, err := t.client()
	if err != nil {
		return "", wrapAgentErr(err)
	}
	ms := int(timeoutOr(timeout, 120*time.Second) / time.Millisecond)
	resp, err := c.Exec(ctx, types.ExecRequest{
		Exe:       exe,
		Args:      args,
		User:      account,
		TimeoutMs: ms,
	})
	if err != nil {
		return "", wrapAgentErr(err)
	}
	out := strings.TrimSpace(resp.Stdout)
	if resp.Stderr != "" {
		if out != "" {
			out += "\n"
		}
		out += strings.TrimSpace(resp.Stderr)
	}
	if resp.Error != "" && resp.ExitCode != 0 {
		if out != "" {
			return out, fmt.Errorf("%s (exit %d)", resp.Error, resp.ExitCode)
		}
		return "", fmt.Errorf("%s (exit %d)", resp.Error, resp.ExitCode)
	}
	if resp.ExitCode != 0 {
		if out == "" {
			out = fmt.Sprintf("exit %d", resp.ExitCode)
		}
		return out, fmt.Errorf("guest exec exit %d", resp.ExitCode)
	}
	return out, nil
}

func (t *agentTransport) CopyTo(ctx context.Context, hostPath, guestDest string) error {
	c, err := t.client()
	if err != nil {
		return wrapAgentErr(err)
	}
	abs, err := filepath.Abs(hostPath)
	if err != nil {
		return err
	}
	if err := c.PutFile(ctx, guestDest, abs); err != nil {
		return wrapAgentErr(err)
	}
	return nil
}

func (t *agentTransport) CopyFrom(ctx context.Context, guestPath, hostPath string) error {
	c, err := t.client()
	if err != nil {
		return wrapAgentErr(err)
	}
	if err := os.MkdirAll(filepath.Dir(hostPath), 0o755); err != nil {
		return err
	}
	if err := c.GetFile(ctx, guestPath, hostPath); err != nil {
		return wrapAgentErr(err)
	}
	return nil
}

func (t *agentTransport) Mkdir(ctx context.Context, guestDir string) error {
	// PUT creates parent directories; a tiny marker is not required.
	_ = guestpaths.CanonWindows(guestDir)
	_, err := t.Run(ctx, UserSystem, `C:\Windows\System32\cmd.exe`, []string{"/c", "mkdir", guestDir}, 30*time.Second)
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "already") {
		return err
	}
	return nil
}

func (t *agentTransport) Remove(ctx context.Context, guestPath string) error {
	c, err := t.client()
	if err != nil {
		return wrapAgentErr(err)
	}
	if err := c.DeleteFile(ctx, guestPath); err != nil {
		return wrapAgentErr(err)
	}
	return nil
}
