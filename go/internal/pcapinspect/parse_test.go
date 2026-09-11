package pcapinspect

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestPacketFromLayersAndAggregate(t *testing.T) {
	raw := `[
	  {"_source":{"layers":{
	    "frame.time_epoch":["1789119560.670275000"],
	    "_ws.col.protocol":["DNS"],
	    "ip.src":["10.66.0.15"],
	    "ip.dst":["10.66.0.1"],
	    "udp.srcport":["62124"],
	    "udp.dstport":["53"],
	    "udp.stream":["4"],
	    "frame.len":["84"],
	    "dns.qry.name":["example.test"],
	    "_ws.col.info":["Standard query A example.test"]
	  }}},
	  {"_source":{"layers":{
	    "frame.time_epoch":["1789119560.688000000"],
	    "_ws.col.protocol":["DNS"],
	    "ip.src":["10.66.0.1"],
	    "ip.dst":["10.66.0.15"],
	    "udp.srcport":["53"],
	    "udp.dstport":["62124"],
	    "udp.stream":["4"],
	    "frame.len":["164"],
	    "dns.qry.name":["example.test"],
	    "_ws.col.info":["Standard query response A 1.2.3.4"]
	  }}},
	  {"_source":{"layers":{
	    "frame.time_epoch":["1789119559.155850000"],
	    "_ws.col.protocol":["TCP"],
	    "ip.src":["10.66.0.1"],
	    "ip.dst":["10.66.0.15"],
	    "tcp.srcport":["57459"],
	    "tcp.dstport":["9443"],
	    "tcp.stream":["7"],
	    "frame.len":["58"],
	    "_ws.col.info":["57459 → 9443 [SYN]"]
	  }}},
	  {"_source":{"layers":{
	    "frame.time_epoch":["1789119560.340601000"],
	    "_ws.col.protocol":["ARP"],
	    "_ws.col.info":["Who has 10.66.0.1? Tell 10.66.0.15"]
	  }}}
	]`
	pkts, err := parsePacketsJSON([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkts) != 4 {
		t.Fatalf("packets %d", len(pkts))
	}
	flows := aggregateFlows(pkts)
	if len(flows) != 3 {
		t.Fatalf("flows %d: %+v", len(flows), flows)
	}
	var dns, agent, arp *Flow
	for i := range flows {
		switch flows[i].Protocol {
		case "DNS":
			dns = &flows[i]
		case "Agent":
			agent = &flows[i]
		case "ARP":
			arp = &flows[i]
		}
	}
	if dns == nil || dns.ID != "udp:4" || dns.Packets != 2 || len(dns.Names) != 1 {
		t.Fatalf("dns: %+v", dns)
	}
	if agent == nil || agent.ID != "tcp:7" || agent.DstPort != 9443 {
		t.Fatalf("agent: %+v", agent)
	}
	if arp == nil || arp.Transport != "arp" {
		t.Fatalf("arp: %+v", arp)
	}
	if _, err := json.Marshal(flows); err != nil {
		t.Fatal(err)
	}
}

func TestDisplayFilterForIDRejectsInjection(t *testing.T) {
	if _, _, _, err := DisplayFilterForID("tcp:1; file"); err == nil {
		t.Fatal("expected reject")
	}
	if _, _, _, err := DisplayFilterForID("icmp:1.2.3.4>evil or true"); err == nil {
		t.Fatal("expected reject")
	}
	_, stream, filter, err := DisplayFilterForID("udp:12")
	if err != nil || stream != 12 || filter != "udp.stream eq 12" {
		t.Fatalf("%d %q %v", stream, filter, err)
	}
	_, _, filter, err = DisplayFilterForID("icmp:10.66.0.15>10.66.0.1")
	if err != nil || !strings.Contains(filter, "ip.src==10.66.0.15") {
		t.Fatalf("%q %v", filter, err)
	}
}

func TestParseFollow(t *testing.T) {
	raw := []byte("\r\n===================================================================\nFollow: tcp,ascii\nFilter: tcp.stream eq 7\nNode 0: 10.66.0.1:57459\nNode 1: 10.66.0.15:9443\n129\nGET /health HTTP/1.1\r\n\r\n")
	p := parseFollow(raw)
	if p.node0 != "10.66.0.1:57459" || p.node1 != "10.66.0.15:9443" {
		t.Fatalf("%+v", p)
	}
	if !strings.Contains(p.body, "GET /health") {
		t.Fatalf("body %q", p.body)
	}
}

func TestParsePacketsJSONEmpty(t *testing.T) {
	pkts, err := parsePacketsJSON([]byte("[]"))
	if err != nil || len(pkts) != 0 {
		t.Fatalf("%v %d", err, len(pkts))
	}
}

func TestListFlowsLivePCAP(t *testing.T) {
	pcap := os.Getenv("QUARANTINE_TEST_PCAP")
	if pcap == "" {
		pcap = `D:\Vbox\LabVM\logs\manifests\Evidence-20260911-103959-network\capture.pcap`
	}
	if _, err := os.Stat(pcap); err != nil {
		t.Skip("no evidence pcap")
	}
	if _, err := FindTshark(); err != nil {
		t.Skip(err)
	}
	flows, err := ListFlows(pcap)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) == 0 {
		t.Fatal("expected non-http flows")
	}
	seen := map[string]bool{}
	for _, f := range flows {
		seen[f.Protocol] = true
		if f.ID == "" || f.Transport == "" {
			t.Fatalf("incomplete %+v", f)
		}
	}
	if !seen["DNS"] && !seen["MDNS"] {
		t.Fatalf("expected DNS/MDNS in %v", seen)
	}
}
