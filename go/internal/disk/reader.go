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
	// VDIPaths is the differencing chain, leaf first, then parents toward the base VDI.
	VDIPaths []string
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

type flattenWait struct {
	done chan struct{}
	path string
	err  error
}

// Reader reads files from snapshot VDI chains (flatten cache is last-resort).
type Reader struct {
	Cfg      *config.Config
	VBox     *vbox.Client
	Index    *Index
	mu       sync.Mutex
	cache    map[string]string // snapshot UUID -> flattened vdi path
	inflight map[string]*flattenWait
}

// NewReader creates a disk reader.
func NewReader(cfg *config.Config, vb *vbox.Client) (*Reader, error) {
	idx, err := ParseVBoxIndex(cfg)
	if err != nil {
		return nil, err
	}
	return &Reader{
		Cfg:      cfg,
		VBox:     vb,
		Index:    idx,
		cache:    map[string]string{},
		inflight: map[string]*flattenWait{},
	}, nil
}

// CacheDir returns temp cache directory for flattened VDIs.
func (r *Reader) CacheDir() string {
	base := filepath.Join(os.TempDir(), "quarantine-lab", "disks")
	_ = os.MkdirAll(base, 0o755)
	return base
}

// resolveSnapshotEntry looks up snapshot disk metadata without cloning.
func (r *Reader) resolveSnapshotEntry(snapshotName string) (SnapshotEntry, error) {
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
			return SnapshotEntry{}, err
		}
		entry = SnapshotEntry{Name: snapshotName, UUID: uuid}
		if idx, err := ParseVBoxIndex(r.Cfg); err == nil {
			if e2, ok2 := idx.Snapshots[strings.ToLower(snapshotName)]; ok2 {
				entry = e2
			}
		}
	}
	return entry, nil
}

func flattenFallbackEnabled() bool {
	v := strings.TrimSpace(os.Getenv("QUARANTINE_DISK_FLATTEN"))
	return v == "1" || strings.EqualFold(v, "true")
}

func (r *Reader) flattenCachePath(entry SnapshotEntry) string {
	return filepath.Join(r.CacheDir(), strings.Trim(entry.UUID, "{}")+".raw")
}

// HasSnapshotChain reports whether the snapshot's VDI leaf and parents exist on disk.
func (r *Reader) HasSnapshotChain(snapshotName string) bool {
	if r == nil {
		return false
	}
	entry, err := r.resolveSnapshotEntry(snapshotName)
	if err != nil || len(entry.VDIPaths) == 0 {
		return false
	}
	for _, p := range entry.VDIPaths {
		st, err := os.Stat(p)
		if err != nil || st.IsDir() {
			return false
		}
	}
	return true
}

// CanReadSnapshot reports whether a VDI chain or an existing RAW flatten can be opened.
// Never starts CloneMedium.
func (r *Reader) CanReadSnapshot(snapshotName string) bool {
	return r.HasSnapshotChain(snapshotName) || r.HasUsableFlattenCache(snapshotName)
}

// HasUsableFlattenCache reports whether a prior CloneMedium RAW for this snapshot
// already exists. Never starts a flatten.
func (r *Reader) HasUsableFlattenCache(snapshotName string) bool {
	entry, err := r.resolveSnapshotEntry(snapshotName)
	if err != nil || entry.UUID == "" {
		return false
	}
	out := r.flattenCachePath(entry)
	r.mu.Lock()
	defer r.mu.Unlock()
	if cached, ok := r.cache[entry.UUID]; ok {
		if _, err := os.Stat(cached); err == nil && isUsableFlattenCache(cached) {
			return true
		}
	}
	if _, err := os.Stat(out); err == nil && isUsableFlattenCache(out) {
		r.cache[entry.UUID] = out
		return true
	}
	return false
}

// openSnapshotDisk opens a linear view of the snapshot disk. Chain first; existing
// RAW cache next; CloneMedium only when allowFlatten is true.
func (r *Reader) openSnapshotDisk(snapshotName string, allowFlatten bool) (*snapshotView, error) {
	entry, err := r.resolveSnapshotEntry(snapshotName)
	if err != nil {
		return nil, err
	}
	var chainErr error
	if len(entry.VDIPaths) > 0 {
		view, err := openVDIChain(entry.VDIPaths)
		if err == nil {
			return view, nil
		}
		chainErr = err
	}
	if r.HasUsableFlattenCache(snapshotName) {
		path := r.flattenCachePath(entry)
		r.mu.Lock()
		if cached, ok := r.cache[entry.UUID]; ok {
			path = cached
		}
		r.mu.Unlock()
		view, err := openVDIChain([]string{path})
		if err == nil {
			return view, nil
		}
		if chainErr == nil {
			chainErr = err
		}
	}
	if allowFlatten {
		path, err := r.EnsureFlattened(snapshotName)
		if err != nil {
			if chainErr != nil {
				return nil, fmt.Errorf("%v; flatten: %w", chainErr, err)
			}
			return nil, err
		}
		return openVDIChain([]string{path})
	}
	if chainErr != nil {
		return nil, chainErr
	}
	return nil, fmt.Errorf("snapshot %q: no VDI chain in .vbox", snapshotName)
}

// EnsureFlattened returns path to flattened VDI for snapshot name.
func (r *Reader) EnsureFlattened(snapshotName string) (string, error) {
	entry, err := r.resolveSnapshotEntry(snapshotName)
	if err != nil {
		return "", err
	}
	uuidClean := strings.Trim(entry.UUID, "{}")
	out := filepath.Join(r.CacheDir(), uuidClean+".raw")

	r.mu.Lock()
	if cached, ok := r.cache[entry.UUID]; ok {
		if _, err := os.Stat(cached); err == nil && isUsableFlattenCache(cached) {
			r.mu.Unlock()
			return cached, nil
		}
	}
	if _, err := os.Stat(out); err == nil {
		if isUsableFlattenCache(out) {
			r.cache[entry.UUID] = out
			r.mu.Unlock()
			return out, nil
		}
		_ = os.Remove(out)
	}
	if wait, ok := r.inflight[entry.UUID]; ok {
		r.mu.Unlock()
		<-wait.done
		return wait.path, wait.err
	}
	wait := &flattenWait{done: make(chan struct{})}
	r.inflight[entry.UUID] = wait
	r.mu.Unlock()

	// Legacy dynamic VDI caches are not linear and cannot be read by go-ntfs.
	legacyVDI := filepath.Join(r.CacheDir(), uuidClean+".vdi")
	if _, err := os.Stat(legacyVDI); err == nil {
		_ = os.Remove(legacyVDI)
	}
	medium := entry.DiskMediumUUID
	if medium == "" && len(entry.VDIPaths) > 0 {
		medium = entry.VDIPaths[0]
	}
	var flattenErr error
	if medium == "" {
		flattenErr = fmt.Errorf("snapshot %q: no disk medium found in .vbox (re-parse VM config)", snapshotName)
	} else if err := r.VBox.CloneMedium(medium, out); err != nil {
		flattenErr = fmt.Errorf("flatten snapshot disk: %w", err)
	}

	r.mu.Lock()
	delete(r.inflight, entry.UUID)
	wait.path = out
	wait.err = flattenErr
	if flattenErr == nil {
		r.cache[entry.UUID] = out
	}
	close(wait.done)
	r.mu.Unlock()
	if flattenErr != nil {
		return "", flattenErr
	}
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
	view, err := r.openSnapshotDisk(snapshotName, flattenFallbackEnabled())
	if err != nil {
		return nil, err
	}
	defer view.Close()
	entries, err := ntfsListDir(view, guestPath)
	if err != nil {
		return nil, err
	}
	for i := range entries {
		entries[i].SnapshotName = snapshotName
	}
	return entries, nil
}

// ReadFile reads file bytes from the snapshot VDI chain using go-ntfs.
// Does not start CloneMedium unless QUARANTINE_DISK_FLATTEN=1.
// If maxBytes <= 0, allows up to 512 MiB (for hive extraction). Files larger
// than maxBytes return the first maxBytes and the full size on FileInfo.
func (r *Reader) ReadFile(snapshotName, guestPath string, maxBytes int64) ([]byte, *FileInfo, error) {
	return r.readFile(snapshotName, guestPath, maxBytes, flattenFallbackEnabled())
}

func (r *Reader) readFile(snapshotName, guestPath string, maxBytes int64, allowFlatten bool) ([]byte, *FileInfo, error) {
	guestPath = normalizeGuestPath(guestPath)
	if maxBytes <= 0 {
		maxBytes = 512 * 1024 * 1024
	}
	view, err := r.openSnapshotDisk(snapshotName, allowFlatten)
	if err != nil {
		return nil, nil, err
	}
	defer view.Close()
	data, size, err := tryNTFSRead(view, guestPath, maxBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s from snapshot %s: %w", guestPath, snapshotName, err)
	}
	return data, &FileInfo{Path: guestPath, Size: size, SnapshotName: snapshotName}, nil
}

// ExtractFile writes a guest file from the snapshot disk to destPath on the host.
// Tries the VDI chain first; CloneMedium only if the chain cannot be opened.
func (r *Reader) ExtractFile(snapshotName, guestPath, destPath string) (int64, error) {
	data, info, err := r.readFile(snapshotName, guestPath, 0, true)
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
