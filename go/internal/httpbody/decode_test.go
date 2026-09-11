package httpbody

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/base64"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/snappy"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"github.com/ulikunitz/xz"
)

func latin1Body(raw []byte) string {
	rs := make([]rune, len(raw))
	for i, c := range raw {
		rs[i] = rune(c)
	}
	return string(rs)
}

func TestDecodeBrotliLatin1(t *testing.T) {
	var buf bytes.Buffer
	w := brotli.NewWriter(&buf)
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	res := Decode("latin-1", "br", latin1Body(buf.Bytes()))
	if res.Error != "" || res.Body != "hello" || res.Decompressed != "br" {
		t.Fatalf("%+v", res)
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
	res := Decode("latin-1", "gzip", latin1Body(buf.Bytes()))
	if res.Error != "" || res.Body != `{"a":1}` {
		t.Fatalf("%+v", res)
	}
}

func TestNeedsDecode(t *testing.T) {
	for _, ce := range []string{"br", "gzip", "deflate", "zstd", "compress", "bzip2", "lz4", "xz", "snappy", "x-gzip", "x-compress"} {
		if !NeedsDecode(ce) {
			t.Fatalf("NeedsDecode(%q)=false", ce)
		}
	}
	if NeedsDecode("identity") || NeedsDecode("") || NeedsDecode("dcb") {
		t.Fatal("NeedsDecode mismatch")
	}
}

func TestDecodeGzipSniffWithoutContentEncoding(t *testing.T) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte(`{"event":"$pageview"}`)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	body := latin1Body(buf.Bytes())
	res := Decode("latin-1", "", body)
	if res.Error != "" || res.Decompressed != "gzip" || res.Body != `{"event":"$pageview"}` {
		t.Fatalf("%+v", res)
	}
	if !BodyLooksGzip("latin-1", body) || !BodyLooksCompressed("latin-1", body) {
		t.Fatal("sniff helpers")
	}
}

func TestDecodeZstd(t *testing.T) {
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := enc.EncodeAll([]byte("self.addEventListener('fetch',()=>{});"), nil)
	_ = enc.Close()
	body := latin1Body(raw)
	res := Decode("latin-1", "zstd", body)
	if res.Error != "" || res.Decompressed != "zstd" || res.Body != "self.addEventListener('fetch',()=>{});" {
		t.Fatalf("%+v", res)
	}
	res2 := Decode("latin-1", "", body)
	if res2.Error != "" || res2.Decompressed != "zstd" {
		t.Fatalf("sniff: %+v", res2)
	}
}

func TestDecodeLZ4XZSnappy(t *testing.T) {
	plain := []byte("plain-text-body-for-codec-tests")

	var lz4buf bytes.Buffer
	zw := lz4.NewWriter(&lz4buf)
	if _, err := zw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if res := Decode("latin-1", "lz4", latin1Body(lz4buf.Bytes())); res.Error != "" || res.Body != string(plain) {
		t.Fatalf("lz4: %+v", res)
	}

	var xzbuf bytes.Buffer
	xzw, err := xz.NewWriter(&xzbuf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xzw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := xzw.Close(); err != nil {
		t.Fatal(err)
	}
	if res := Decode("latin-1", "xz", latin1Body(xzbuf.Bytes())); res.Error != "" || res.Body != string(plain) {
		t.Fatalf("xz: %+v", res)
	}

	framed := snappy.Encode(nil, plain) // block format
	if res := Decode("latin-1", "snappy", latin1Body(framed)); res.Error != "" || res.Body != string(plain) {
		t.Fatalf("snappy: %+v", res)
	}
}

func TestDecodeDeflateBase64Wrapped(t *testing.T) {
	var raw bytes.Buffer
	w, err := flate.NewWriter(&raw, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(raw.Bytes())
	res := Decode("utf-8", "deflate", b64)
	if res.Error != "" || res.Body != `{"ok":true}` || res.Decompressed != "deflate" {
		t.Fatalf("%+v", res)
	}
}

func TestDecodeMislabeledGzipAsDeflate(t *testing.T) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte("mislabeled")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	res := Decode("latin-1", "deflate", latin1Body(buf.Bytes()))
	if res.Error != "" || res.Body != "mislabeled" || res.Decompressed != "gzip" {
		t.Fatalf("%+v", res)
	}
}
