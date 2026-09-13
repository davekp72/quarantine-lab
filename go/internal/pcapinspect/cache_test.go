package pcapinspect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestListFlowsUsesSidecarCache(t *testing.T) {
	dir := t.TempDir()
	pcap := filepath.Join(dir, "capture.pcap")
	if err := os.WriteFile(pcap, []byte("not-a-real-pcap"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(pcap)
	if err != nil {
		t.Fatal(err)
	}
	want := []Flow{{
		ID:        "udp:4",
		Transport: "udp",
		Protocol:  "DNS",
		SrcIP:     "10.66.0.15",
		DstIP:     "10.66.0.1",
		Names:     []string{"example.test"},
	}}
	saveFlowCache(pcap, st, want)

	flows, cached, err := ListFlowsCached(pcap)
	if err != nil {
		t.Fatal(err)
	}
	if !cached {
		t.Fatal("expected cache hit (no tshark)")
	}
	if len(flows) != 1 || flows[0].ID != "udp:4" || flows[0].Names[0] != "example.test" {
		t.Fatalf("%+v", flows)
	}
	flows[0].Protocol = "mutated"
	again, _, err := ListFlowsCached(pcap)
	if err != nil || again[0].Protocol != "DNS" {
		t.Fatalf("cache should return a copy: %+v %v", again, err)
	}
}

func TestListFlowsCacheInvalidatesOnSizeChange(t *testing.T) {
	dir := t.TempDir()
	pcap := filepath.Join(dir, "capture.pcap")
	if err := os.WriteFile(pcap, []byte("tiny"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(pcap)
	if err != nil {
		t.Fatal(err)
	}
	saveFlowCache(pcap, st, []Flow{{ID: "udp:1", Transport: "udp", Protocol: "DNS"}})
	if err := os.WriteFile(pcap, []byte("much-larger-dummy"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, cached, err := ListFlowsCached(pcap)
	if cached {
		t.Fatalf("stale cache should miss (err=%v)", err)
	}
}
