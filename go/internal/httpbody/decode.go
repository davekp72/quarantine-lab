package httpbody

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/andybalholm/brotli"
)

const maxDecodedBytes = 2 << 20 // 2 MiB display cap

// DecodeResult is a body ready for the network detail pane.
type DecodeResult struct {
	Body         string `json:"body"`
	Encoding     string `json:"encoding"`
	Decompressed string `json:"decompressed,omitempty"` // e.g. "br", "gzip"
	Truncated    bool   `json:"truncated,omitempty"`
	Error        string `json:"error,omitempty"`
}

// Decode turns a captured wire body into display text.
// bodyEncoding is the capture encoding (utf-8|latin-1|base64).
// contentEncoding is the HTTP Content-Encoding header value.
func Decode(bodyEncoding, contentEncoding, body string) DecodeResult {
	bodyEncoding = strings.ToLower(strings.TrimSpace(bodyEncoding))
	if bodyEncoding == "" {
		bodyEncoding = "utf-8"
	}
	raw, err := bodyToBytes(bodyEncoding, body)
	if err != nil {
		return DecodeResult{Body: body, Encoding: bodyEncoding, Error: err.Error()}
	}
	encs := parseContentEncodings(contentEncoding)
	if len(encs) == 0 {
		return textResult(raw, "")
	}
	decoded := raw
	applied := make([]string, 0, len(encs))
	for i := len(encs) - 1; i >= 0; i-- {
		enc := encs[i]
		next, derr := decompressOnce(decoded, enc)
		if derr != nil {
			// Not compressed / already plain — return original text path.
			if len(applied) == 0 {
				return textResult(raw, "")
			}
			return DecodeResult{
				Body:         body,
				Encoding:     bodyEncoding,
				Error:        fmt.Sprintf("decompress %s: %v", enc, derr),
				Decompressed: strings.Join(applied, ","),
			}
		}
		decoded = next
		applied = append(applied, enc)
	}
	res := textResult(decoded, strings.Join(applied, ","))
	return res
}

// NeedsDecode reports whether Content-Encoding implies compression.
func NeedsDecode(contentEncoding string) bool {
	return len(parseContentEncodings(contentEncoding)) > 0
}

// ContentEncodingFromHeaders picks Content-Encoding from a header map.
func ContentEncodingFromHeaders(headers map[string]any) string {
	if headers == nil {
		return ""
	}
	for k, v := range headers {
		if strings.EqualFold(strings.TrimSpace(k), "content-encoding") {
			return fmt.Sprint(v)
		}
	}
	return ""
}

func parseContentEncodings(h string) []string {
	var out []string
	for _, part := range strings.Split(h, ",") {
		e := strings.ToLower(strings.TrimSpace(part))
		e = strings.Split(e, ";")[0]
		e = strings.TrimSpace(e)
		switch e {
		case "", "identity":
			continue
		case "gzip", "x-gzip", "deflate", "br", "brotli":
			if e == "brotli" {
				e = "br"
			}
			if e == "x-gzip" {
				e = "gzip"
			}
			out = append(out, e)
		}
	}
	return out
}

func bodyToBytes(encoding, body string) ([]byte, error) {
	switch encoding {
	case "base64":
		return base64.StdEncoding.DecodeString(strings.TrimSpace(body))
	case "latin-1", "iso-8859-1", "latin1":
		// Prefer strict U+00xx (JSON latin-1). If the string was mangled in transit,
		// fall back to low-byte / UTF-8 bytes so view-time decode can still try.
		out := make([]byte, 0, len(body))
		strictOK := true
		for _, r := range body {
			if r > 255 {
				strictOK = false
				break
			}
			out = append(out, byte(r))
		}
		if strictOK {
			return out, nil
		}
		// Mangled preview (e.g. PowerShell pipe): try UTF-8 bytes of the string.
		return []byte(body), nil
	default:
		// utf-8 stored as Go/JSON string — use raw UTF-8 bytes.
		return []byte(body), nil
	}
}

func decompressOnce(in []byte, enc string) ([]byte, error) {
	switch enc {
	case "gzip":
		r, err := gzip.NewReader(bytes.NewReader(in))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return readLimitedAllowPartial(r)
	case "deflate":
		if zr, err := zlib.NewReader(bytes.NewReader(in)); err == nil {
			out, err2 := readLimitedAllowPartial(zr)
			_ = zr.Close()
			if err2 == nil || len(out) > 0 {
				return out, nil
			}
		}
		r := flate.NewReader(bytes.NewReader(in))
		defer r.Close()
		return readLimitedAllowPartial(r)
	case "br":
		return readLimitedAllowPartial(brotli.NewReader(bytes.NewReader(in)))
	default:
		return nil, fmt.Errorf("unsupported content-encoding %q", enc)
	}
}

func readLimited(r io.Reader) ([]byte, error) {
	return readLimitedAllowPartial(r)
}

// readLimitedAllowPartial returns up to maxDecodedBytes. Truncated compressed
// captures (gateway MAX_BODY) often end with UnexpectedEOF after valid prefix.
func readLimitedAllowPartial(r io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	_, err := io.Copy(&buf, io.LimitReader(r, maxDecodedBytes+1))
	out := buf.Bytes()
	if len(out) > 0 && err != nil {
		return out, nil
	}
	return out, err
}

func textResult(raw []byte, decompressed string) DecodeResult {
	truncated := len(raw) > maxDecodedBytes
	if truncated {
		raw = raw[:maxDecodedBytes]
	}
	res := DecodeResult{Decompressed: decompressed, Truncated: truncated}
	if utf8.Valid(raw) && looksMostlyText(raw) {
		res.Body = string(raw)
		res.Encoding = "utf-8"
		return res
	}
	// Round-trip binary as latin-1 so the pane still shows something.
	b := make([]byte, len(raw))
	copy(b, raw)
	res.Body = string(b)
	res.Encoding = "latin-1"
	return res
}

func looksMostlyText(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	bad := 0
	for _, c := range b {
		if c == 0 {
			bad++
			continue
		}
		if c < 9 || (c > 13 && c < 32) {
			bad++
		}
	}
	return float64(bad)/float64(len(b)) < 0.05
}
