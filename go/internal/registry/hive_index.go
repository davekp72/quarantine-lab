package registry

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	IndexSuffix     = "-registry-index.jsonl.gz"
	IndexMetaSuffix = "-registry-meta.json"
	IndexFormatSlim = "slim-fnv64-json"
)

// IndexRecord is one registry value in the sorted hive index.
type IndexRecord struct {
	K    string `json:"k"`
	N    string `json:"n"`
	T    string `json:"t"`
	V    any    `json:"v,omitempty"`
	H    string `json:"h"`
	Size int    `json:"s,omitempty"`
}

// SortKey returns the stable merge-join key.
func (r IndexRecord) SortKey() string {
	return strings.ToLower(r.K) + "|" + strings.ToLower(r.N)
}

// ContentHash hashes type + serialized value for equality checks (tests / legacy).
func ContentHash(typ string, value any) string {
	return contentHashRaw(0, []byte(typ+"\x00"+fmt.Sprint(value)))
}

// IndexMeta describes a built hive index sidecar.
type IndexMeta struct {
	Engine     string     `json:"engine"`
	Format     string     `json:"format,omitempty"`
	Snapshot   string     `json:"snapshot"`
	BuiltAt    string     `json:"builtAt"`
	EntryCount int        `json:"entryCount"`
	Hives      []HiveMeta `json:"hives"`
	// Source is informational (e.g. live-reg-save); not shown as a warning banner.
	Source   string            `json:"source,omitempty"`
	Warnings []string          `json:"warnings,omitempty"`
	Digests  map[string]string `json:"digests,omitempty"`
}

// HiveMeta is one extracted hive contribution.
type HiveMeta struct {
	GuestPath string `json:"guestPath"`
	Prefix    string `json:"prefix"`
	Entries   int    `json:"entries"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256,omitempty"`
	Error     string `json:"error,omitempty"`
}

// WriteIndexSorted writes records as gzip JSONL (sorted by SortKey if needed).
func WriteIndexSorted(path string, records []IndexRecord) error {
	if !recordsSorted(records) {
		sortRecords(records)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewWriterLevel(f, gzip.BestSpeed)
	if err != nil {
		return err
	}
	buf := make([]byte, 0, 512)
	for _, rec := range records {
		buf = appendIndexLine(buf[:0], rec)
		if _, err := gz.Write(buf); err != nil {
			_ = gz.Close()
			return err
		}
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return f.Close()
}

func recordsSorted(records []IndexRecord) bool {
	for i := 1; i < len(records); i++ {
		if records[i].SortKey() < records[i-1].SortKey() {
			return false
		}
	}
	return true
}

func appendIndexLine(buf []byte, rec IndexRecord) []byte {
	buf = append(buf, `{"k":`...)
	buf = appendJSONString(buf, rec.K)
	buf = append(buf, `,"n":`...)
	buf = appendJSONString(buf, rec.N)
	buf = append(buf, `,"t":`...)
	buf = appendJSONString(buf, rec.T)
	buf = append(buf, `,"h":`...)
	buf = appendJSONString(buf, rec.H)
	if rec.Size > 0 {
		buf = append(buf, `,"s":`...)
		buf = strconv.AppendInt(buf, int64(rec.Size), 10)
	}
	if rec.V != nil {
		buf = append(buf, `,"v":`...)
		raw, err := json.Marshal(rec.V)
		if err == nil {
			buf = append(buf, raw...)
		} else {
			buf = append(buf, `null`...)
		}
	}
	return append(buf, "}\n"...)
}

func appendJSONString(buf []byte, s string) []byte {
	raw, err := json.Marshal(s)
	if err != nil {
		return append(buf, `""`...)
	}
	return append(buf, raw...)
}

// WriteIndexMeta writes registry index metadata JSON.
func WriteIndexMeta(path string, meta IndexMeta) error {
	raw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

// ReadIndexMeta loads index metadata if present.
func ReadIndexMeta(path string) (*IndexMeta, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m IndexMeta
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// IndexExists reports whether both index and meta sidecars exist.
func IndexExists(indexPath, metaPath string) bool {
	if _, err := os.Stat(indexPath); err != nil {
		return false
	}
	if _, err := os.Stat(metaPath); err != nil {
		return false
	}
	return true
}

// OpenIndexReader opens a gzip JSONL index for sequential reading.
type IndexReader struct {
	f   *os.File
	gz  *gzip.Reader
	sc  *bufio.Scanner
	rec IndexRecord
	err error
	eof bool
}

func OpenIndex(path string) (*IndexReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	sc := bufio.NewScanner(gz)
	buf := make([]byte, 0, 1024*1024)
	sc.Buffer(buf, 16*1024*1024)
	return &IndexReader{f: f, gz: gz, sc: sc}, nil
}

func (r *IndexReader) Close() error {
	var err error
	if r.gz != nil {
		err = r.gz.Close()
	}
	if r.f != nil {
		if e := r.f.Close(); e != nil && err == nil {
			err = e
		}
	}
	return err
}

// Next advances to the next record. Returns false on EOF or error.
func (r *IndexReader) Next() bool {
	if r.eof || r.err != nil {
		return false
	}
	if !r.sc.Scan() {
		r.eof = true
		if e := r.sc.Err(); e != nil {
			r.err = e
		}
		return false
	}
	line := r.sc.Bytes()
	var rec IndexRecord
	if err := json.Unmarshal(line, &rec); err != nil {
		r.err = err
		return false
	}
	r.rec = rec
	return true
}

func (r *IndexReader) Record() IndexRecord { return r.rec }
func (r *IndexReader) Err() error          { return r.err }

const maxInlineValueBytes = 4 * 1024

// ValueForStorage returns inline value or nil when only hash should be kept.
func ValueForStorage(typ string, raw any, data []byte) (v any, size int, keep bool) {
	size = len(data)
	if size == 0 && raw != nil {
		size = len(fmt.Sprint(raw))
	}
	if size > maxInlineValueBytes {
		return nil, size, false
	}
	switch typ {
	case "REG_SZ", "REG_EXPAND_SZ", "REG_DWORD", "REG_QWORD", "REG_MULTI_SZ":
		return raw, size, true
	default:
		if size <= 256 {
			return raw, size, true
		}
		return nil, size, false
	}
}

func normalizeRegKey(prefix, path string) string {
	prefix = strings.TrimRight(prefix, `\`)
	path = strings.Trim(path, `\`)
	if path == "" {
		return prefix
	}
	return prefix + `\` + path
}
