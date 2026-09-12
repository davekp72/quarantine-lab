package guest

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/vbox"
)

const (
	UserSystem  = "system"
	UserGuest   = "guest"
	UserPayload = "payload"
)

// Transport is the host↔Windows-guest control plane (agent HTTP or VBox guestcontrol).
type Transport interface {
	Name() string
	Ready(ctx context.Context) error
	Run(ctx context.Context, account, exe string, args []string, timeout time.Duration) (string, error)
	CopyTo(ctx context.Context, hostPath, guestDest string) error
	CopyFrom(ctx context.Context, guestPath, hostPath string) error
	Mkdir(ctx context.Context, guestDir string) error
	Remove(ctx context.Context, guestPath string) error
}

// NewTransport selects agent (default) or guestcontrol.
func NewTransport(cfg *config.Config, vb *vbox.Client) Transport {
	if cfg != nil && cfg.UseGuestAdditions() {
		return newGuestControlTransport(cfg, vb)
	}
	return newAgentTransport(cfg)
}

func timeoutOr(d, fallback time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return fallback
}

func wrapAgentErr(err error) error {
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "agent request") ||
		strings.Contains(msg, "connectex") ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "wsarecv") ||
		strings.Contains(msg, "eof") {
		return fmt.Errorf("%s", config.AgentUnreachableHint(err))
	}
	return err
}
