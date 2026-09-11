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
	attachSnapshotHTTP(cfgPath, result)
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
