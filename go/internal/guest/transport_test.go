package guest

import (
	"testing"

	"github.com/quarantine-lab/quarantine/internal/config"
)

func TestEffectiveTransportSelection(t *testing.T) {
	t.Cleanup(func() { config.GuestAdditionsCLI = false })
	cfg := &config.Config{}
	cfg.Guest.Transport = ""
	if NewTransport(cfg, nil).Name() != config.TransportAgent {
		t.Fatal("empty transport should be agent")
	}
	cfg.Guest.Transport = config.TransportGuestControl
	if NewTransport(cfg, nil).Name() != config.TransportGuestControl {
		t.Fatal("config guestcontrol")
	}
	cfg.Guest.Transport = config.TransportAgent
	config.GuestAdditionsCLI = true
	if NewTransport(cfg, nil).Name() != config.TransportGuestControl {
		t.Fatal("CLI flag should override to guestcontrol")
	}
	config.GuestAdditionsCLI = false
	if NewTransport(cfg, nil).Name() != config.TransportAgent {
		t.Fatal("flag off should be agent")
	}
}
