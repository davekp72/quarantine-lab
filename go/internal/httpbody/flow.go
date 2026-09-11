package httpbody

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// FlowPart is request or response from flows.jsonl.
type FlowPart struct {
	ContentType   string         `json:"contentType"`
	BodyBytes     int            `json:"bodyBytes"`
	BodyTruncated bool           `json:"bodyTruncated"`
	Encoding      string         `json:"encoding"`
	Body          string         `json:"body"`
	Headers       map[string]any `json:"headers"`
}

// FlowRecord is one mitm flows.jsonl line.
type FlowRecord struct {
	T           string   `json:"t"`
	Method      string   `json:"method"`
	URL         string   `json:"url"`
	Host        string   `json:"host"`
	Path        string   `json:"path"`
	Status      any      `json:"status"`
	ResolvedIPs []string `json:"resolvedIps"`
	Request     *FlowPart `json:"request"`
	Response    *FlowPart `json:"response"`
}

// ReadFlowLine reads 1-based line number from a flows.jsonl file.
func ReadFlowLine(path string, lineNo int) (*FlowRecord, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "" || lineNo < 1 {
		return nil, fmt.Errorf("invalid flow path/line")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// Large JS bundles — allow big lines (default 64K is too small).
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 8<<20)

	n := 0
	for sc.Scan() {
		n++
		if n < lineNo {
			continue
		}
		var rec FlowRecord
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return nil, fmt.Errorf("parse flow line %d: %w", lineNo, err)
		}
		return &rec, nil
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("flow line %d not found in %s", lineNo, path)
}

// DecodePart returns a display-ready copy of a flow part (decompress Content-Encoding).
func DecodePart(p *FlowPart) map[string]any {
	if p == nil {
		return nil
	}
	out := map[string]any{
		"contentType":   p.ContentType,
		"bodyBytes":     p.BodyBytes,
		"bodyTruncated": p.BodyTruncated,
		"encoding":      p.Encoding,
		"body":          p.Body,
		"headers":       p.Headers,
	}
	ce := ContentEncodingFromHeaders(p.Headers)
	if !NeedsDecode(ce) && !BodyLooksGzip(p.Encoding, p.Body) {
		return out
	}
	res := Decode(p.Encoding, ce, p.Body)
	out["body"] = res.Body
	out["encoding"] = res.Encoding
	if res.Decompressed != "" {
		out["decompressed"] = res.Decompressed
	}
	if res.Truncated {
		out["bodyTruncated"] = true
	}
	if res.Error != "" {
		out["decodeError"] = res.Error
	}
	return out
}

// AllowedFlowPath reports whether path is under one of the allowed roots.
func AllowedFlowPath(path string, roots ...string) bool {
	path = filepath.Clean(path)
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	for _, root := range roots {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		rabs, err := filepath.Abs(filepath.Clean(root))
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(rabs, abs)
		if err != nil {
			continue
		}
		if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
			return true
		}
	}
	return false
}
