package guest

import (
	"context"
	"path/filepath"
	"time"

	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/vbox"
)

type gcTransport struct {
	cfg *config.Config
	vb  *vbox.Client
}

func newGuestControlTransport(cfg *config.Config, vb *vbox.Client) Transport {
	return &gcTransport{cfg: cfg, vb: vb}
}

func (t *gcTransport) Name() string { return config.TransportGuestControl }

func (t *gcTransport) creds(account string) (user, pass string) {
	switch account {
	case UserPayload:
		return t.cfg.Payload.Username, t.cfg.Payload.Password
	default:
		return t.cfg.Guest.Username, t.cfg.Guest.Password
	}
}

func (t *gcTransport) Ready(ctx context.Context) error {
	_, err := t.Run(ctx, UserGuest, `C:\Windows\System32\cmd.exe`, []string{"/c", "echo", "ok"}, 30*time.Second)
	return err
}

func (t *gcTransport) Run(ctx context.Context, account, exe string, args []string, timeout time.Duration) (string, error) {
	user, pass := t.creds(account)
	return t.vb.GuestControlRun(t.cfg.VMName, user, pass, exe, args, timeoutOr(timeout, 120*time.Second))
}

func (t *gcTransport) CopyTo(ctx context.Context, hostPath, guestDest string) error {
	user, pass := t.creds(UserGuest)
	abs, err := filepath.Abs(hostPath)
	if err != nil {
		return err
	}
	parent := filepath.Dir(guestDest)
	_ = t.vb.GuestControlMkdir(t.cfg.VMName, user, pass, parent, timeoutOr(0, 45*time.Second))
	return t.vb.GuestControlCopyTo(t.cfg.VMName, user, pass, abs, guestDest, timeoutOr(0, t.timeout()))
}

func (t *gcTransport) CopyFrom(ctx context.Context, guestPath, hostPath string) error {
	user, pass := t.creds(UserGuest)
	return t.vb.GuestControlCopyFrom(t.cfg.VMName, user, pass, guestPath, hostPath, timeoutOr(0, t.timeout()))
}

func (t *gcTransport) Mkdir(ctx context.Context, guestDir string) error {
	user, pass := t.creds(UserGuest)
	return t.vb.GuestControlMkdir(t.cfg.VMName, user, pass, guestDir, timeoutOr(0, 45*time.Second))
}

func (t *gcTransport) Remove(ctx context.Context, guestPath string) error {
	user, pass := t.creds(UserGuest)
	_, err := t.vb.GuestControlRun(
		t.cfg.VMName, user, pass,
		`C:\Windows\System32\cmd.exe`,
		[]string{"/c", "del", "/f", "/q", guestPath, "&", "rmdir", "/s", "/q", guestPath},
		30*time.Second,
	)
	return err
}

func (t *gcTransport) timeout() time.Duration {
	if t.cfg != nil && t.cfg.Guest.TimeoutMs > 0 {
		return time.Duration(t.cfg.Guest.TimeoutMs) * time.Millisecond
	}
	return 120 * time.Second
}
