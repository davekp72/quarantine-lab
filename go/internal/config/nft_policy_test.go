package config

import (
	"strings"
	"testing"
)

func TestNormalizeTrafficModeDefaultsFakeNet(t *testing.T) {
	got, err := NormalizeTrafficMode("")
	if err != nil || got != "fakenet" {
		t.Fatalf("empty: got %q %v", got, err)
	}
	got, err = NormalizeTrafficMode("permissive")
	if err != nil || got != "permissive" {
		t.Fatalf("permissive: got %q %v", got, err)
	}
}

func TestPermissiveForwardRulesNoBlanketAccept(t *testing.T) {
	p := DefaultPermissivePolicy()
	fwd := p.PermissiveForwardRules()
	if strings.Contains(fwd, "oifname \"__WAN__\" accept\n") && !strings.Contains(fwd, "tcp dport") {
		t.Fatalf("must not blanket-accept WAN:\n%s", fwd)
	}
	if strings.Contains(fwd, "iifname \"__LAN__\" oifname \"__WAN__\" accept") {
		t.Fatalf("blanket accept still present:\n%s", fwd)
	}
	if !strings.Contains(fwd, "udp dport { 53, 853 } drop") {
		t.Fatalf("expected DNS/DoT drop:\n%s", fwd)
	}
	if strings.Contains(fwd, "tcp dport { 80") {
		t.Fatalf("80/443 should not be WAN-forwarded:\n%s", fwd)
	}
}

func TestPermissiveExtraPort(t *testing.T) {
	p := DefaultPermissivePolicy()
	p.TCPPorts = []int{80, 443, 22, 8443}
	fwd := p.PermissiveForwardRules()
	if !strings.Contains(fwd, "tcp dport { 22, 8443 } accept") {
		t.Fatalf("expected extra TCP allow:\n%s", fwd)
	}
}

func TestPermissiveNATForceDNS(t *testing.T) {
	p := DefaultPermissivePolicy()
	nat := p.PermissiveNATRules()
	if !strings.Contains(nat, "udp dport 53 redirect") {
		t.Fatalf("expected DNS redirect:\n%s", nat)
	}
	off := false
	p.ForceDNSToGateway = &off
	nat = p.PermissiveNATRules()
	if strings.Contains(nat, "redirect") {
		t.Fatalf("force DNS off should not redirect:\n%s", nat)
	}
}
