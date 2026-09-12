package diff

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadNetworkHTTPFromFlows(t *testing.T) {
	dir := t.TempDir()
	body := strings.Join([]string{
		`{"t":"2026-09-11T13:52:34Z","method":"GET","url":"https://example.com/a","host":"example.com","status":200,"request":{"body":"ok\u0007"},"response":{"body":"x"}}`,
		`{"t":"2026-09-11T13:52:35Z","method":"GET","url":"http://127.0.0.1/quarantine.pac","host":"127.0.0.1"}`,
		`{"t":"2026-09-11T13:52:36Z","method":"POST","url":"https://web.whatsapp.com/","host":"web.whatsapp.com","status":200}`,
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "flows.jsonl"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	reqs, srcs := ReadNetworkHTTP(dir)
	if len(srcs) != 1 {
		t.Fatalf("sources=%v", srcs)
	}
	if len(reqs) != 2 {
		t.Fatalf("got %d reqs: %+v", len(reqs), reqs)
	}
	if reqs[0]["host"] != "example.com" {
		t.Fatalf("first host=%v", reqs[0]["host"])
	}
	if reqs[1]["host"] != "web.whatsapp.com" {
		t.Fatalf("second host=%v", reqs[1]["host"])
	}
	if _, ok := reqs[0]["request"]; ok {
		t.Fatal("list rows must not embed bodies")
	}
	if reqs[0]["flowLine"] != 1 {
		t.Fatalf("flowLine=%v", reqs[0]["flowLine"])
	}
}

func TestReadNetworkHTTPFallsBackToAccessLog(t *testing.T) {
	dir := t.TempDir()
	raw := "2026-09-11T13:52:34Z GET https://config.edge.skype.com/x\n" +
		"2026-09-11T13:52:35Z GET http://10.66.0.1/mitmproxy-ca-cert.cer\n"
	if err := os.WriteFile(filepath.Join(dir, "access.log"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	reqs, _ := ReadNetworkHTTP(dir)
	if len(reqs) != 1 {
		t.Fatalf("got %d", len(reqs))
	}
	if reqs[0]["host"] != "config.edge.skype.com" {
		t.Fatalf("host=%v", reqs[0]["host"])
	}
}

func TestReadNetworkHTTPPrefersURLHostOverIP(t *testing.T) {
	dir := t.TempDir()
	body := `{"t":"2026-09-12T16:30:45Z","method":"GET","url":"https://en.wikipedia.org/wiki/Main_Page","host":"185.15.59.224","status":200}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "flows.jsonl"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	reqs, _ := ReadNetworkHTTP(dir)
	if len(reqs) != 1 {
		t.Fatalf("got %d", len(reqs))
	}
	if reqs[0]["host"] != "en.wikipedia.org" {
		t.Fatalf("host=%v want en.wikipedia.org", reqs[0]["host"])
	}
}

func TestAttachSnapshotHTTPRecoversAfterJSONParseFailure(t *testing.T) {
	dir := t.TempDir()
	netDir := filepath.Join(dir, "Evidence-x-network")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(netDir, "flows.jsonl"), []byte(
		`{"t":"2026-09-11T13:52:34Z","method":"GET","url":"https://example.com/","host":"example.com","status":200}`+"\n",
	), 0o644); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(cfgPath, []byte(`{"manifest":{"logDir":"`+strings.ReplaceAll(dir, `\`, `\\`)+`"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	result := &Result{
		Meta: MetaSection{ToSnapshot: "Evidence-x"},
		Network: &NetworkSection{
			Message:  `Network JSON parse failed: invalid character '\a' in string literal`,
			Sources:  map[string]any{"proxyLogs": []any{}, "pcaps": []any{}},
			DNS:      []map[string]any{},
			Requests: []map[string]any{},
		},
	}
	attachSnapshotHTTP(cfgPath, result, "", "")
	if len(result.Network.Requests) != 1 {
		t.Fatalf("requests=%d", len(result.Network.Requests))
	}
	if result.Summary.NetworkRequests != 1 {
		t.Fatalf("summary=%d", result.Summary.NetworkRequests)
	}
	if strings.Contains(strings.ToLower(result.Network.Message), "json parse failed") {
		t.Fatalf("message still parse error: %s", result.Network.Message)
	}
}

func TestFilterHTTPBySnapshotWindowAbsolute(t *testing.T) {
	reqs := []map[string]any{
		{"t": "2026-09-12T15:10:00Z", "url": "https://old.example/"},
		{"t": "2026-09-12T15:49:00Z", "url": "https://in.example/"},
		{"t": "2026-09-12T16:30:00Z", "url": "https://late.example/"},
	}
	got := FilterHTTPBySnapshotWindow(reqs, "2026-09-12T15:48:33Z", "2026-09-12T15:50:02Z")
	if len(got) != 1 || got[0]["url"] != "https://in.example/" {
		t.Fatalf("got=%v", got)
	}
}

func TestFilterHTTPBySnapshotWindowDurationTail(t *testing.T) {
	// Guest window short; package ~50m ahead so absolute (±30m) misses entirely.
	reqs := []map[string]any{
		{"t": "2026-09-12T14:00:00Z", "url": "https://leftover.example/"},
		{"t": "2026-09-12T16:39:00Z", "url": "https://a.example/"},
		{"t": "2026-09-12T16:40:00Z", "url": "https://b.example/"},
	}
	got := FilterHTTPBySnapshotWindow(reqs, "2026-09-12T15:48:33Z", "2026-09-12T15:50:02Z")
	if len(got) != 2 {
		t.Fatalf("want duration-tail 2, got %d: %v", len(got), got)
	}
	if got[0]["url"] == "https://leftover.example/" {
		t.Fatalf("leftover should be dropped: %v", got)
	}
}

func TestDedupDNSByQueryDropsIPs(t *testing.T) {
	rows := []map[string]any{
		{"t": "1", "query": "google.com", "source": "pcap"},
		{"t": "2", "query": "google.com", "source": "sysmon"},
		{"t": "3", "query": "1.2.3.4", "source": "mitm"},
	}
	got := DedupDNSByQuery(rows)
	if len(got) != 1 || got[0]["source"] != "sysmon" {
		t.Fatalf("got=%v", got)
	}
}
