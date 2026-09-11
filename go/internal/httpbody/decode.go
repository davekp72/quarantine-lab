package httpbody

import (
	"bytes"
	"compress/bzip2"
	"compress/flate"
	"compress/gzip"
	"compress/lzw"
	"compress/zlib"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/snappy"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"github.com/ulikunitz/xz"
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
		if snif := sniffContentEncoding(raw); snif != "" {
			encs = []string{snif}
		} else {
			return textResult(raw, "")
		}
	}
	decoded := raw
	applied := make([]string, 0, len(encs))
	for i := len(encs) - 1; i >= 0; i-- {
		enc := encs[i]
		next, derr := decompressOnce(decoded, enc)
		if derr != nil {
			// Labeled encoding failed — try magic sniff once (mislabeled CE).
			if len(applied) == 0 {
				if snif := sniffContentEncoding(decoded); snif != "" && snif != enc {
					if alt, aerr := decompressOnce(decoded, snif); aerr == nil {
						decoded = alt
						applied = append(applied, snif)
						continue
					}
				}
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
	return textResult(decoded, strings.Join(applied, ","))
}

// NeedsDecode reports whether Content-Encoding implies compression.
func NeedsDecode(contentEncoding string) bool {
	return len(parseContentEncodings(contentEncoding)) > 0
}

func isGzipMagic(b []byte) bool {
	return len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b
}

func isZstdMagic(b []byte) bool {
	return len(b) >= 4 && b[0] == 0x28 && b[1] == 0xb5 && b[2] == 0x2f && b[3] == 0xfd
}

func isZlibMagic(b []byte) bool {
	// zlib CMF/FLG: CMF=0x78 common; header must be multiple of 31.
	if len(b) < 2 || b[0]&0x0f != 8 {
		return false
	}
	return int(b[0])<<8|int(b[1])%31 == 0
}

func isCompressMagic(b []byte) bool {
	return len(b) >= 2 && b[0] == 0x1f && b[1] == 0x9d
}

func isBzip2Magic(b []byte) bool {
	return len(b) >= 3 && b[0] == 'B' && b[1] == 'Z' && b[2] == 'h'
}

func isXzMagic(b []byte) bool {
	return len(b) >= 6 &&
		b[0] == 0xfd && b[1] == '7' && b[2] == 'z' &&
		b[3] == 'X' && b[4] == 'Z' && b[5] == 0x00
}

func isLz4FrameMagic(b []byte) bool {
	return len(b) >= 4 && b[0] == 0x04 && b[1] == 0x22 && b[2] == 0x4d && b[3] == 0x18
}

func isSnappyFramedMagic(b []byte) bool {
	return len(b) >= 4 && b[0] == 0xff && b[1] == 0x06 && b[2] == 0x00 && b[3] == 0x00
}

// sniffContentEncoding guesses a single content-coding from wire magic.
func sniffContentEncoding(b []byte) string {
	switch {
	case isGzipMagic(b):
		return "gzip"
	case isZstdMagic(b):
		return "zstd"
	case isCompressMagic(b):
		return "compress"
	case isBzip2Magic(b):
		return "bzip2"
	case isXzMagic(b):
		return "xz"
	case isLz4FrameMagic(b):
		return "lz4"
	case isSnappyFramedMagic(b):
		return "snappy"
	case isZlibMagic(b):
		return "deflate"
	default:
		return ""
	}
}

// BodyLooksGzip reports whether a captured body starts with gzip magic.
func BodyLooksGzip(bodyEncoding, body string) bool {
	raw, err := bodyToBytes(bodyEncoding, body)
	return err == nil && isGzipMagic(raw)
}

// BodyLooksCompressed reports recognizable compressed-body magic.
func BodyLooksCompressed(bodyEncoding, body string) bool {
	raw, err := bodyToBytes(bodyEncoding, body)
	return err == nil && sniffContentEncoding(raw) != ""
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
		case "gzip", "x-gzip":
			out = append(out, "gzip")
		case "deflate":
			out = append(out, "deflate")
		case "br", "brotli":
			out = append(out, "br")
		case "zstd":
			out = append(out, "zstd")
		case "compress", "x-compress":
			out = append(out, "compress")
		case "bzip2", "bz2", "x-bzip2":
			out = append(out, "bzip2")
		case "lz4", "lz4frame", "x-lz4":
			out = append(out, "lz4")
		case "xz", "lzma", "x-xz":
			out = append(out, "xz")
		case "snappy", "x-snappy-framed":
			out = append(out, "snappy")
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
		return decompressDeflate(in)
	case "br":
		return readLimitedAllowPartial(brotli.NewReader(bytes.NewReader(in)))
	case "zstd":
		r, err := zstd.NewReader(bytes.NewReader(in))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return readLimitedAllowPartial(r)
	case "compress":
		return decompressCompress(in)
	case "bzip2":
		return readLimitedAllowPartial(bzip2.NewReader(bytes.NewReader(in)))
	case "lz4":
		return decompressLZ4(in)
	case "xz":
		r, err := xz.NewReader(bytes.NewReader(in))
		if err != nil {
			return nil, err
		}
		return readLimitedAllowPartial(r)
	case "snappy":
		return decompressSnappy(in)
	default:
		return nil, fmt.Errorf("unsupported content-encoding %q", enc)
	}
}

func decompressDeflate(in []byte) ([]byte, error) {
	if zr, err := zlib.NewReader(bytes.NewReader(in)); err == nil {
		out, err2 := readLimitedAllowPartial(zr)
		_ = zr.Close()
		if err2 == nil || len(out) > 0 {
			return out, nil
		}
	}
	r := flate.NewReader(bytes.NewReader(in))
	out, err := readLimitedAllowPartial(r)
	_ = r.Close()
	if err == nil || len(out) > 0 {
		return out, nil
	}
	// Some clients (e.g. Microsoft OneCollector) send base64(raw-deflate)
	// while advertising Content-Encoding: deflate.
	if b64, ok := decodeASCIIBase64(in); ok {
		r2 := flate.NewReader(bytes.NewReader(b64))
		out2, err2 := readLimitedAllowPartial(r2)
		_ = r2.Close()
		if err2 == nil || len(out2) > 0 {
			return out2, nil
		}
		if zr, zerr := zlib.NewReader(bytes.NewReader(b64)); zerr == nil {
			out3, err3 := readLimitedAllowPartial(zr)
			_ = zr.Close()
			if err3 == nil || len(out3) > 0 {
				return out3, nil
			}
		}
	}
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("deflate: empty")
}

func decodeASCIIBase64(in []byte) ([]byte, bool) {
	if len(in) < 16 {
		return nil, false
	}
	s := strings.TrimSpace(string(in))
	if s == "" {
		return nil, false
	}
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '+' || c == '/' || c == '=' || c == '-' || c == '_' ||
			c == '\n' || c == '\r' {
			continue
		}
		return nil, false
	}
	enc := base64.StdEncoding
	if strings.ContainsAny(s, "-_") {
		enc = base64.URLEncoding
	}
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s)
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	out, err := enc.DecodeString(s)
	if err != nil || len(out) == 0 {
		return nil, false
	}
	return out, true
}

func decompressCompress(in []byte) ([]byte, error) {
	// Unix compress: 1f 9d <maxbits> + LZW (LSB).
	if !isCompressMagic(in) || len(in) < 3 {
		return nil, fmt.Errorf("compress: bad magic")
	}
	r := lzw.NewReader(bytes.NewReader(in[3:]), lzw.LSB, 8)
	defer r.Close()
	return readLimitedAllowPartial(r)
}

func decompressLZ4(in []byte) ([]byte, error) {
	r := lz4.NewReader(bytes.NewReader(in))
	out, err := readLimitedAllowPartial(r)
	if err == nil || len(out) > 0 {
		return out, nil
	}
	// Unframed block fallback.
	buf := make([]byte, maxDecodedBytes+1)
	n, err2 := lz4.UncompressBlock(in, buf)
	if err2 != nil {
		if err != nil {
			return nil, err
		}
		return nil, err2
	}
	if n > maxDecodedBytes {
		return buf[:maxDecodedBytes], nil
	}
	return buf[:n], nil
}

func decompressSnappy(in []byte) ([]byte, error) {
	if isSnappyFramedMagic(in) {
		r := snappy.NewReader(bytes.NewReader(in))
		return readLimitedAllowPartial(r)
	}
	out, err := snappy.Decode(nil, in)
	if err != nil {
		// Last resort: framed reader even without magic.
		r := snappy.NewReader(bytes.NewReader(in))
		return readLimitedAllowPartial(r)
	}
	if len(out) > maxDecodedBytes {
		return out[:maxDecodedBytes], nil
	}
	return out, nil
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
