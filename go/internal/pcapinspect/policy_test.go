package pcapinspect

import (
	"testing"

	"github.com/quarantine-lab/quarantine/internal/config"
)

func TestAnnotatePolicyBreaches(t *testing.T) {
	pol := config.DefaultPermissivePolicy()
	flows := []Flow{
		{Transport: "tcp", Protocol: "HTTPS", SrcIP: "10.66.0.15", DstIP: "1.2.3.4", DstPort: 443},
		{Transport: "tcp", Protocol: "SSH", SrcIP: "10.66.0.15", DstIP: "1.2.3.4", DstPort: 22},
		{Transport: "udp", Protocol: "DNS", SrcIP: "10.66.0.15", DstIP: "8.8.8.8", DstPort: 53},
		{Transport: "udp", Protocol: "DNS", SrcIP: "10.66.0.15", DstIP: "10.66.0.1", DstPort: 53},
		{Transport: "tcp", Protocol: "SSH", SrcIP: "10.66.0.15", DstIP: "10.66.0.1", DstPort: 22},
		{Transport: "icmp", Protocol: "ICMP", SrcIP: "10.66.0.15", DstIP: "1.1.1.1"},
	}
	AnnotatePolicyBreaches(flows, pol, "10.66.0.0/24", "10.66.0.1", "10.66.0.15")
	if flows[0].PolicyBreach {
		t.Fatal("HTTPS should be allowlisted")
	}
	if !flows[1].PolicyBreach {
		t.Fatal("SSH to WAN should breach")
	}
	if !flows[2].PolicyBreach {
		t.Fatal("DNS to 8.8.8.8 should breach when forceDns")
	}
	if flows[3].PolicyBreach {
		t.Fatal("DNS to gateway is allowed")
	}
	if flows[4].PolicyBreach {
		t.Fatal("SSH to gateway is lab traffic")
	}
	if flows[5].PolicyBreach {
		t.Fatal("ICMP allowed by default")
	}
}
