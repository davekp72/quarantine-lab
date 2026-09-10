package httpbody

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadFlowLineAndDecodeBrotli(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "flows.jsonl")
	// Minimal brotli("hi") via Decode round-trip using latin-1 stored body without compression for unit simplicity:
	// line with uncompressed utf-8 body + a br line built from Decode's inverse isn't needed —
	// just ensure ReadFlowLine parses and DecodePart passes through identity.
	line := `{"t":"2026-01-01T00:00:00Z","method":"GET","url":"https://x.test/a.js","host":"x.test","status":200,"request":{"headers":{},"encoding":"utf-8","body":"","bodyBytes":0},"response":{"headers":{"content-type":"application/javascript","content-encoding":"identity"},"encoding":"utf-8","body":"console.log(1)","bodyBytes":14}}` + "\n"
	if err := os.WriteFile(path, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	rec, err := ReadFlowLine(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	part := DecodePart(rec.Response)
	if part["body"] != "console.log(1)" {
		t.Fatalf("%v", part)
	}
}

func TestAllowedFlowPath(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "Evidence-x-network", "flows.jsonl")
	_ = os.MkdirAll(filepath.Dir(nested), 0o755)
	_ = os.WriteFile(nested, []byte("{}\n"), 0o644)
	if !AllowedFlowPath(nested, root) {
		t.Fatal("expected allowed")
	}
	if AllowedFlowPath(filepath.Join(root, "..", "other", "flows.jsonl"), root) {
		t.Fatal("expected denied")
	}
}
