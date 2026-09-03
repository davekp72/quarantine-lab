package disk

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/vbox"
)

// SnapshotEntry maps snapshot name to UUID and media files.
type SnapshotEntry struct {
	Name           string
	UUID           string
	Parent         string
	Time           time.Time
	DiskMediumUUID string
	VDIPaths       []string
}

// Index parses .vbox snapshot tree.
type Index struct {
	VMName    string
	VBoxFile  string
	BaseVDI   string
	Snapshots map[string]SnapshotEntry // keyed by lower name
}

// ParseVBoxIndex loads snapshot metadata from .vbox file.
func ParseVBoxIndex(cfg *config.Config) (*Index, error) {
	vboxFile := cfg.VBoxFile()
	raw, err := os.ReadFile(vboxFile)
	if err != nil {
		return nil, fmt.Errorf("read vbox: %w", err)
	}
	idx := &Index{
		VMName:    cfg.VMName,
		VBoxFile:  vboxFile,
		BaseVDI:   cfg.DiskPathResolved(),
		Snapshots: parseSnapshotIndex(raw, cfg.VMFolder()),
	}
	return idx, nil
}

// Reader reads files from snapshot disks via cached flatten.
type Reader struct {
	Cfg   *config.Config
	VBox  *vbox.Client
	Index *Index
	mu    sync.Mutex
	cache map[string]string // snapshot UUID -> flattened vdi path
}

// NewReader creates a disk reader.
func NewReader(cfg *config.Config, vb *vbox.Client) (*Reader, error) {
	idx, err := ParseVBoxIndex(cfg)
	if err != nil {
		return nil, err
	}
	return &Reader{Cfg: cfg, VBox: vb, Index: idx, cache: map[string]string{}}, nil
}

// CacheDir returns temp cache directory for flattened VDIs.
func (r *Reader) CacheDir() string {
	base := filepath.Join(os.TempDir(), "quarantine-lab", "disks")
	_ = os.MkdirAll(base, 0o755)
	return base
}

// EnsureFlattened returns path to flattened VDI for snapshot name.
func (r *Reader) EnsureFlattened(snapshotName string) (string, error) {
	entry, ok := r.Index.Snapshots[strings.ToLower(snapshotName)]
	if !ok || entry.DiskMediumUUID == "" {
		if idx, err := ParseVBoxIndex(r.Cfg); err == nil {
			if e2, ok2 := idx.Snapshots[strings.ToLower(snapshotName)]; ok2 {
				entry = e2
				ok = true
			}
		}
	}
	if !ok {
		uuid, err := r.VBox.SnapshotUUID(r.Cfg.VMName, snapshotName)
		if err != nil {
			return "", err
		}
		entry = SnapshotEntry{Name: snapshotName, UUID: uuid}
		if idx, err := ParseVBoxIndex(r.Cfg); err == nil {
			if e2, ok2 := idx.Snapshots[strings.ToLower(snapshotName)]; ok2 {
				entry = e2
			}
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if cached, ok := r.cache[entry.UUID]; ok {
		if _, err := os.Stat(cached); err == nil && isUsableFlattenCache(cached) {
			return cached, nil
		}
	}
	uuidClean := strings.Trim(entry.UUID, "{}")
	out := filepath.Join(r.CacheDir(), uuidClean+".raw")
	if _, err := os.Stat(out); err == nil {
		if isUsableFlattenCache(out) {
			r.cache[entry.UUID] = out
			return out, nil
		}
		_ = os.Remove(out)
	}
	// Legacy dynamic VDI caches are not linear and cannot be read by go-ntfs.
	legacyVDI := filepath.Join(r.CacheDir(), uuidClean+".vdi")
	if _, err := os.Stat(legacyVDI); err == nil {
		_ = os.Remove(legacyVDI)
	}
	medium := entry.DiskMediumUUID
	if medium == "" && len(entry.VDIPaths) > 0 {
		medium = entry.VDIPaths[0]
	}
	if medium == "" {
		return "", fmt.Errorf("snapshot %q: no disk medium found in .vbox (re-parse VM config)", snapshotName)
	}
	if err := r.VBox.CloneMedium(medium, out); err != nil {
		return "", fmt.Errorf("flatten snapshot disk: %w", err)
	}
	r.cache[entry.UUID] = out
	return out, nil
}

// FileInfo describes a guest file path request.
type FileInfo struct {
	Path         string `json:"path"`
	Size         int64  `json:"size"`
	Modified     string `json:"modified,omitempty"`
	IsDirectory  bool   `json:"isDirectory"`
	SnapshotName string `json:"snapshotName"`
}

// ListDirectory lists immediate children under a guest path.
func (r *Reader) ListDirectory(snapshotName, guestPath string) ([]FileInfo, error) {
	guestPath = normalizeGuestPath(guestPath)
	vdi, err := r.EnsureFlattened(snapshotName)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(vdi)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := ntfsListDir(f, guestPath)
	if err != nil {
		return nil, err
	}
	for i := range entries {
		entries[i].SnapshotName = snapshotName
	}
	return entries, nil
}

// ReadFile reads file bytes from snapshot disk using go-ntfs when available.
// If maxBytes <= 0, allows up to 512 MiB (for hive extraction).
func (r *Reader) ReadFile(snapshotName, guestPath string, maxBytes int64) ([]byte, *FileInfo, error) {
	guestPath = normalizeGuestPath(guestPath)
	vdi, err := r.EnsureFlattened(snapshotName)
	if err != nil {
		return nil, nil, err
	}
	if maxBytes <= 0 {
		maxBytes = 512 * 1024 * 1024
	}
	data, info, err := readNTFSFile(vdi, guestPath, maxBytes)
	if err != nil {
		return nil, nil, err
	}
	info.SnapshotName = snapshotName
	return data, info, nil
}

// ExtractFile writes a guest file from the snapshot disk to destPath on the host.
func (r *Reader) ExtractFile(snapshotName, guestPath, destPath string) (int64, error) {
	data, info, err := r.ReadFile(snapshotName, guestPath, 0)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return 0, err
	}
	if err := os.WriteFile(destPath, data, 0o644); err != nil {
		return 0, err
	}
	if info != nil {
		return info.Size, nil
	}
	return int64(len(data)), nil
}

func normalizeGuestPath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.ReplaceAll(p, `/`, `\`)
	if !strings.Contains(p, ":") && !strings.HasPrefix(p, `\`) {
		p = `C:\` + strings.TrimPrefix(p, `\`)
	}
	return p
}

func trimSlash(p string) string {
	for len(p) > 0 && (p[0] == '/' || p[0] == '\\') {
		p = p[1:]
	}
	return p
}

// readNTFSFile reads a file from a flattened VDI via go-ntfs.
func readNTFSFile(vdiPath, guestPath string, maxBytes int64) ([]byte, *FileInfo, error) {
	f, err := os.Open(vdiPath)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	data, size, err := tryNTFSRead(f, guestPath, maxBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s from %s: %w (flatten cache: %s)", guestPath, vdiPath, err, vdiPath)
	}
	return data, &FileInfo{Path: guestPath, Size: size}, nil
}

func isUsableFlattenCache(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var hdr [0x60]byte
	if _, err := f.ReadAt(hdr[:], 0); err != nil {
		return false
	}
	if bytes.HasPrefix(hdr[:], []byte("<<<<<<< Oracle VM VirtualBox")) {
		// Only fixed VDI is linear enough; dynamic VDI (type 1) uses a block map.
		if binary.LittleEndian.Uint32(hdr[0x4c:0x50]) == 1 {
			return false
		}
	}
	_, err = ntfsPartitionReader(f)
	return err == nil
}

func tryNTFSRead(r io.ReaderAt, guestPath string, maxBytes int64) ([]byte, int64, error) {
	return ntfsReadFile(r, guestPath, maxBytes)
}
