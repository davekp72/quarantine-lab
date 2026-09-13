package cases

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/diff"
)

const (
	dirName         = "cases"
	metaFile        = "meta.json"
	compareFile     = "compare.json"
	bodiesDir       = "bodies"
	bodiesIndexFile = "bodies-index.json"
	networkDirName  = "network"
)

// Meta describes a saved compare pack.
type Meta struct {
	ID            string `json:"id"`
	FromSnapshot  string `json:"fromSnapshot"`
	ToSnapshot    string `json:"toSnapshot"`
	FromCaptured  string `json:"fromCaptured,omitempty"`
	ToCaptured    string `json:"toCaptured,omitempty"`
	ExcludeNoise  bool   `json:"excludeNoise"`
	CreatedAt     string `json:"createdAt"`
	NetworkCopied bool   `json:"networkCopied"`
	FileBodies    int    `json:"fileBodies"`
	Bytes         int64  `json:"bytes,omitempty"`
}

// Body is one side of an archived guest file.
type Body struct {
	Data        []byte
	Truncated   bool
	Unavailable bool
	Reason      string
}

// BodyEntry is the on-disk index row for one guest path.
type BodyEntry struct {
	FromRel       string `json:"from,omitempty"`
	ToRel         string `json:"to,omitempty"`
	FromTruncated bool   `json:"fromTruncated,omitempty"`
	ToTruncated   bool   `json:"toTruncated,omitempty"`
	FromUnavail   bool   `json:"fromUnavailable,omitempty"`
	ToUnavail     bool   `json:"toUnavailable,omitempty"`
	FromReason    string `json:"fromReason,omitempty"`
	ToReason      string `json:"toReason,omitempty"`
}

// SaveRequest is a compare result plus loaders used while snapshots still exist.
type SaveRequest struct {
	Result        *diff.Result
	ExcludeNoise  bool
	ToNetworkDir  string
	MaxBodyBytes  int64
	LoadFrom      func(guestPath string) Body
	LoadTo        func(guestPath string) Body
	NoiseDomains  []string
	NoiseFiles    []string
	NoiseRegistry []string
}

// Store reads and writes case packs under {manifest.logDir}/cases/.
type Store struct {
	Root string
}

// NewStore returns a store rooted at the manifest log cases directory.
func NewStore(cfg *config.Config) *Store {
	root := ""
	if cfg != nil {
		root = filepath.Join(cfg.ManifestLogDir(), dirName)
	}
	return &Store{Root: root}
}

func (s *Store) dir(id string) string {
	return filepath.Join(s.Root, config.SafeSnapshotFileName(id))
}

// NetworkDir is the copied To-network folder inside a case.
func (s *Store) NetworkDir(id string) string {
	return filepath.Join(s.dir(id), networkDirName)
}

// ComparePath is compare.json for a case.
func (s *Store) ComparePath(id string) string {
	return filepath.Join(s.dir(id), compareFile)
}

func newCaseID(from, to string) string {
	stamp := time.Now().UTC().Format("20060102T150405.000Z")
	return fmt.Sprintf("%s-%s-vs-%s", stamp, config.SafeSnapshotFileName(from), config.SafeSnapshotFileName(to))
}

func (s *Store) uniqueID(from, to string) string {
	base := newCaseID(from, to)
	id := base
	for n := 2; n < 1000; n++ {
		if _, err := os.Stat(s.dir(id)); err != nil {
			return id
		}
		id = fmt.Sprintf("%s-%d", base, n)
	}
	return fmt.Sprintf("%s-%d", base, time.Now().UnixNano())
}

// Save writes a self-contained case pack. Never copies VDI/RAW disks.
func (s *Store) Save(req SaveRequest) (*Meta, error) {
	if s == nil || strings.TrimSpace(s.Root) == "" {
		return nil, fmt.Errorf("case store root required")
	}
	if req.Result == nil {
		return nil, fmt.Errorf("compare result required")
	}
	archived := diff.FilterResultWith(req.Result, req.ExcludeNoise, req.NoiseDomains, req.NoiseFiles, req.NoiseRegistry)
	if archived == nil {
		return nil, fmt.Errorf("empty compare result")
	}
	id := s.uniqueID(archived.Meta.FromSnapshot, archived.Meta.ToSnapshot)
	dest := s.dir(id)
	if err := os.MkdirAll(filepath.Join(dest, bodiesDir), 0o755); err != nil {
		return nil, err
	}

	index := map[string]BodyEntry{}
	bodies := 0
	max := req.MaxBodyBytes
	if max <= 0 {
		max = 4 * 1024 * 1024
	}

	collect := func(path, side string, load func(string) Body) {
		path = strings.TrimSpace(path)
		if path == "" || load == nil {
			return
		}
		key := normalizeIndexPath(path)
		ent := index[key]
		b := load(path)
		if int64(len(b.Data)) > max {
			b.Data = b.Data[:max]
			b.Truncated = true
		}
		rel, err := writeBodyFile(dest, key, side, b.Data)
		if err == nil && rel != "" {
			bodies++
		}
		if side == "from" {
			ent.FromRel = rel
			ent.FromTruncated = b.Truncated
			ent.FromUnavail = b.Unavailable || (rel == "" && len(b.Data) == 0)
			ent.FromReason = b.Reason
		} else {
			ent.ToRel = rel
			ent.ToTruncated = b.Truncated
			ent.ToUnavail = b.Unavailable || (rel == "" && len(b.Data) == 0)
			ent.ToReason = b.Reason
		}
		if b.Reason == "too_large" {
			if side == "from" {
				ent.FromReason = "too_large"
			} else {
				ent.ToReason = "too_large"
			}
		}
		index[key] = ent
	}

	for _, f := range archived.Files.Added {
		collect(f.Path, "to", req.LoadTo)
	}
	for _, f := range archived.Files.Removed {
		collect(f.Path, "from", req.LoadFrom)
		collect(f.Path, "to", req.LoadTo)
	}
	for _, f := range archived.Files.Modified {
		p := f.Path
		if p == "" {
			p = f.After.Path
		}
		collect(p, "from", req.LoadFrom)
		collect(p, "to", req.LoadTo)
	}

	idxRaw, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dest, bodiesIndexFile), idxRaw, 0o644); err != nil {
		return nil, err
	}

	netCopied := false
	if src := strings.TrimSpace(req.ToNetworkDir); src != "" {
		if st, err := os.Stat(src); err == nil && st.IsDir() {
			if _, err := copyDir(src, filepath.Join(dest, networkDirName)); err != nil {
				return nil, fmt.Errorf("copy network package: %w", err)
			}
			netCopied = true
			rewriteNetworkPaths(archived, filepath.Join(dest, networkDirName))
		}
	}

	archived.Meta.CaseID = id
	archived.Meta.ExcludeNoise = req.ExcludeNoise

	cmpRaw, err := json.MarshalIndent(archived, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dest, compareFile), cmpRaw, 0o644); err != nil {
		return nil, err
	}

	meta := &Meta{
		ID:            id,
		FromSnapshot:  archived.Meta.FromSnapshot,
		ToSnapshot:    archived.Meta.ToSnapshot,
		FromCaptured:  archived.Meta.FromCaptured,
		ToCaptured:    archived.Meta.ToCaptured,
		ExcludeNoise:  req.ExcludeNoise,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		NetworkCopied: netCopied,
		FileBodies:    bodies,
	}
	metaRaw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dest, metaFile), metaRaw, 0o644); err != nil {
		return nil, err
	}
	return meta, nil
}

func writeBodyFile(caseDir, guestPath, side string, data []byte) (string, error) {
	if len(data) == 0 {
		return "", nil
	}
	sum := sha256.Sum256([]byte(strings.ToLower(guestPath)))
	name := hex.EncodeToString(sum[:8]) + "." + side
	rel := filepath.ToSlash(filepath.Join(bodiesDir, name))
	if err := os.WriteFile(filepath.Join(caseDir, filepath.FromSlash(rel)), data, 0o644); err != nil {
		return "", err
	}
	return rel, nil
}

func rewriteNetworkPaths(result *diff.Result, netDir string) {
	if result == nil || result.Network == nil {
		return
	}
	flows := filepath.Join(netDir, "flows.jsonl")
	access := filepath.Join(netDir, "access.log")
	pcap := filepath.Join(netDir, "capture.pcap")
	if _, err := os.Stat(pcap); err != nil {
		if _, err2 := os.Stat(filepath.Join(netDir, "capture.pcapng")); err2 == nil {
			pcap = filepath.Join(netDir, "capture.pcapng")
		}
	}
	for i, req := range result.Network.Requests {
		ff, _ := req["flowFile"].(string)
		switch strings.ToLower(filepath.Base(ff)) {
		case "flows.jsonl":
			req["flowFile"] = flows
		case "access.log", "access-transparent.log":
			if strings.EqualFold(filepath.Base(ff), "access-transparent.log") {
				req["flowFile"] = filepath.Join(netDir, "access-transparent.log")
			} else {
				req["flowFile"] = access
			}
		}
		result.Network.Requests[i] = req
	}
	if result.Network.Sources == nil {
		result.Network.Sources = map[string]any{}
	}
	if _, err := os.Stat(flows); err == nil {
		result.Network.Sources["proxyLogs"] = []string{flows}
	}
	if _, err := os.Stat(pcap); err == nil {
		result.Network.Sources["pcaps"] = []string{pcap}
	}
}

func normalizeIndexPath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.ReplaceAll(p, `/`, `\`)
	return strings.ToLower(p)
}

// List returns case metadata newest first.
func (s *Store) List() ([]Meta, error) {
	if s == nil || s.Root == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(s.Root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Meta
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		m, err := s.LoadMeta(e.Name())
		if err != nil {
			continue
		}
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt > out[j].CreatedAt
	})
	return out, nil
}

// LoadMeta reads meta.json.
func (s *Store) LoadMeta(id string) (*Meta, error) {
	raw, err := os.ReadFile(filepath.Join(s.dir(id), metaFile))
	if err != nil {
		return nil, err
	}
	var m Meta
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m.ID == "" {
		m.ID = id
	}
	return &m, nil
}

// LoadCompare returns the archived diff JSON.
func (s *Store) LoadCompare(id string) ([]byte, *Meta, error) {
	meta, err := s.LoadMeta(id)
	if err != nil {
		return nil, nil, err
	}
	raw, err := os.ReadFile(s.ComparePath(id))
	if err != nil {
		return nil, meta, err
	}
	return raw, meta, nil
}

// Delete removes a case pack.
func (s *Store) Delete(id string) error {
	id = strings.TrimSpace(id)
	if id == "" || strings.ContainsAny(id, `/\`) {
		return fmt.Errorf("invalid case id")
	}
	return os.RemoveAll(s.dir(id))
}

// ReadBodies returns from/to bytes for a guest path.
func (s *Store) ReadBodies(id, guestPath string) (from, to []byte, ent BodyEntry, err error) {
	raw, err := os.ReadFile(filepath.Join(s.dir(id), bodiesIndexFile))
	if err != nil {
		return nil, nil, ent, err
	}
	var idx map[string]BodyEntry
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, nil, ent, err
	}
	key := normalizeIndexPath(guestPath)
	ent, ok := idx[key]
	if !ok {
		for k, v := range idx {
			if strings.EqualFold(k, key) {
				ent = v
				ok = true
				break
			}
		}
	}
	if !ok {
		return nil, nil, ent, fmt.Errorf("no archived body for %s", guestPath)
	}
	from, err = readRel(s.dir(id), ent.FromRel)
	if err != nil {
		return nil, nil, ent, err
	}
	to, err = readRel(s.dir(id), ent.ToRel)
	return from, to, ent, err
}

func readRel(root, rel string) ([]byte, error) {
	rel = strings.TrimSpace(rel)
	if rel == "" {
		return nil, nil
	}
	clean := filepath.Clean(filepath.FromSlash(rel))
	if strings.HasPrefix(clean, "..") {
		return nil, fmt.Errorf("invalid body path")
	}
	p := filepath.Join(root, clean)
	return os.ReadFile(p)
}

func copyDir(src, dst string) (int64, error) {
	var n int64
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if err := copyFile(path, target); err != nil {
			return err
		}
		n += info.Size()
		return nil
	})
	return n, err
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
