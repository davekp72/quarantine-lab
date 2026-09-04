//go:build windows

package diff

import (
	"testing"
)

func TestMergeSysmonDNSIncludesYellow(t *testing.T) {
	result := &Result{
		Network: &NetworkSection{
			Available: true,
			Message:   "Proxy/PCAP sources were scanned but no DNS or HTTP requests matched the snapshot time window.",
			DNS:       []map[string]any{},
			Requests:  []map[string]any{},
		},
	}
	added := []map[string]any{
		{
			"eid":       float64(22),
			"t":         "DnsQuery",
			"queryName": "yellow.com",
			"image":     `C:\WINDOWS\system32\PING.EXE`,
			"time":      "2026-09-04T09:59:36.9850722Z",
		},
		{
			"eid":       float64(22),
			"t":         "DnsQuery",
			"queryName": "client.wns.windows.com",
			"time":      "2026-09-04T09:58:46.8977466Z", // outside window
		},
		{
			"eid":   float64(1),
			"t":     "ProcessCreate",
			"time":  "2026-09-04T09:59:34.1226304Z",
			"image": `C:\Windows\System32\PING.EXE`,
		},
	}
	mergeSysmonDNS(result,
		"2026-09-04T09:59:03.0000000+00:00",
		"2026-09-04T09:59:47.0000000+00:00",
		added)

	if len(result.Network.DNS) != 1 {
		t.Fatalf("dns=%d want 1: %#v", len(result.Network.DNS), result.Network.DNS)
	}
	if result.Network.DNS[0]["query"] != "yellow.com" {
		t.Fatalf("query=%v", result.Network.DNS[0]["query"])
	}
	if result.Network.DNS[0]["source"] != "sysmon" {
		t.Fatalf("source=%v", result.Network.DNS[0]["source"])
	}
	if result.Summary.DNSQueries != 1 {
		t.Fatalf("summary dns=%d", result.Summary.DNSQueries)
	}
}
