package httpbody

import (
	"bytes"
	"compress/gzip"
	"testing"

	"github.com/andybalholm/brotli"
)

func TestDecodeBrotliLatin1(t *testing.T) {
	var buf bytes.Buffer
	w := brotli.NewWriter(&buf)
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	compressed := buf.Bytes()
	rs := make([]rune, len(compressed))
	for i, c := range compressed {
		rs[i] = rune(c)
	}
	body := string(rs)
	res := Decode("latin-1", "br", body)
	if res.Error != "" {
		t.Fatal(res.Error)
	}
	if res.Body != "hello" {
		t.Fatalf("got %q decompressed=%q", res.Body, res.Decompressed)
	}
	if res.Decompressed != "br" {
		t.Fatalf("decompressed=%q", res.Decompressed)
	}
}

func TestDecodeGzip(t *testing.T) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	rs := make([]rune, len(raw))
	for i, c := range raw {
		rs[i] = rune(c)
	}
	res := Decode("latin-1", "gzip", string(rs))
	if res.Error != "" || res.Body != `{"a":1}` {
		t.Fatalf("%+v", res)
	}
}

func TestNeedsDecode(t *testing.T) {
	if !NeedsDecode("br") || NeedsDecode("identity") || NeedsDecode("") {
		t.Fatal("NeedsDecode mismatch")
	}
}
