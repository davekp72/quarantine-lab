package disk

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type testBlk struct {
	free bool
	zero bool
	data []byte
}

func dataBlk(s string) testBlk { return testBlk{data: []byte(s)} }
func freeBlk() testBlk         { return testBlk{free: true} }
func zeroBlk() testBlk         { return testBlk{zero: true} }

func writeTestVDI(t *testing.T, path string, typ uint32, blockSize uint32, blocks []testBlk) {
	t.Helper()
	n := uint32(len(blocks))
	if n == 0 || blockSize < 512 {
		t.Fatal("invalid test VDI geometry")
	}
	const (
		offBmap = 0x200
		offData = 0x1000
	)
	hdr := make([]byte, offData)
	copy(hdr[0:], []byte("<<<<<<< Oracle VM VirtualBox Disk Image >>>>>>>"))
	binary.LittleEndian.PutUint32(hdr[0x40:], vdiSignature)
	binary.LittleEndian.PutUint32(hdr[0x44:], vdiVersion1_1)
	binary.LittleEndian.PutUint32(hdr[0x48:], 0x180)
	binary.LittleEndian.PutUint32(hdr[0x4c:], typ)
	binary.LittleEndian.PutUint32(hdr[0x154:], offBmap)
	binary.LittleEndian.PutUint32(hdr[0x158:], offData)
	binary.LittleEndian.PutUint32(hdr[0x168:], 512) // LegacyGeometry.cbSector
	binary.LittleEndian.PutUint64(hdr[0x170:], uint64(n)*uint64(blockSize))
	binary.LittleEndian.PutUint32(hdr[0x178:], blockSize)
	binary.LittleEndian.PutUint32(hdr[0x17c:], 0)
	binary.LittleEndian.PutUint32(hdr[0x180:], n)

	var alloc uint32
	var payloads [][]byte
	for i, b := range blocks {
		off := int(offBmap) + i*4
		switch {
		case b.free:
			binary.LittleEndian.PutUint32(hdr[off:], vdiBlockFree)
		case b.zero:
			binary.LittleEndian.PutUint32(hdr[off:], vdiBlockZero)
		default:
			binary.LittleEndian.PutUint32(hdr[off:], alloc)
			buf := make([]byte, blockSize)
			copy(buf, b.data)
			payloads = append(payloads, buf)
			alloc++
		}
	}
	binary.LittleEndian.PutUint32(hdr[0x184:], alloc)

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(hdr); err != nil {
		t.Fatal(err)
	}
	for _, p := range payloads {
		if _, err := f.Write(p); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseVDIHeaderSynthetic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "base.vdi")
	writeTestVDI(t, path, vdiTypeDynamic, 4096, []testBlk{dataBlk("hello"), freeBlk()})
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	hdr, err := parseVDIHeader(f)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Type != vdiTypeDynamic || hdr.BlockSize != 4096 || hdr.Blocks != 2 || hdr.DiskSize != 8192 {
		t.Fatalf("hdr=%+v", hdr)
	}
	if hdr.OffBlocks != 0x200 || hdr.OffData != 0x1000 {
		t.Fatalf("offsets bmap=%d data=%d", hdr.OffBlocks, hdr.OffData)
	}
}

func TestVDIChainReaderAt(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.vdi")
	child := filepath.Join(dir, "child.vdi")
	const bs = 4096
	writeTestVDI(t, base, vdiTypeDynamic, bs, []testBlk{
		dataBlk("BASE-BLOCK0"),
		dataBlk("ONLY-BASE"),
		freeBlk(),
		zeroBlk(),
	})
	writeTestVDI(t, child, vdiTypeDiff, bs, []testBlk{
		dataBlk("CHILD-BLOCK0"),
		freeBlk(),
		dataBlk("NEW-IN-CHILD"),
		freeBlk(),
	})

	view, err := openVDIChain([]string{child, base})
	if err != nil {
		t.Fatal(err)
	}
	defer view.Close()

	got := make([]byte, 12)
	if _, err := view.ReadAt(got, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("CHILD-BLOCK0")) {
		t.Fatalf("leaf overlay: %q", got)
	}

	got = make([]byte, 9)
	if _, err := view.ReadAt(got, bs); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("ONLY-BASE")) {
		t.Fatalf("parent fallback: %q", got)
	}

	got = make([]byte, 12)
	if _, err := view.ReadAt(got, 2*bs); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("NEW-IN-CHILD")) {
		t.Fatalf("child-only: %q", got)
	}

	got = make([]byte, 8)
	if _, err := view.ReadAt(got, 3*bs); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, make([]byte, 8)) {
		t.Fatalf("zero block: %q", got)
	}

	// Span the block boundary: zeros at the end of child block 0, then parent data.
	span := make([]byte, 8)
	if _, err := view.ReadAt(span, bs-4); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(span[:4], make([]byte, 4)) || !bytes.Equal(span[4:], []byte("ONLY")) {
		t.Fatalf("span: %q", span)
	}
}

func TestOpenVDIChainRAW(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "disk.raw")
	payload := []byte("RAW-LINEAR-DISK")
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	view, err := openVDIChain([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	defer view.Close()
	got := make([]byte, len(payload))
	if _, err := view.ReadAt(got, 0); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("raw: %q", got)
	}
}

func TestReadFileUsesChainWithoutFlatten(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.vdi")
	child := filepath.Join(dir, "child.vdi")
	writeTestVDI(t, base, vdiTypeDynamic, 4096, []testBlk{dataBlk("BASE"), freeBlk()})
	writeTestVDI(t, child, vdiTypeDiff, 4096, []testBlk{dataBlk("CHILD"), freeBlk()})

	r := &Reader{
		Index: &Index{Snapshots: map[string]SnapshotEntry{
			"snap": {
				Name:           "snap",
				UUID:           "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}",
				DiskMediumUUID: "child",
				VDIPaths:       []string{child, base},
			},
		}},
		cache:    map[string]string{},
		inflight: map[string]*flattenWait{},
	}
	if !r.HasSnapshotChain("snap") || !r.CanReadSnapshot("snap") {
		t.Fatal("expected chain to be readable")
	}
	_, _, err := r.ReadFile("snap", `C:\missing.txt`, 1024)
	if err == nil {
		t.Fatal("expected NTFS parse to fail on synthetic disk")
	}
	if !strings.Contains(err.Error(), "NTFS") && !strings.Contains(err.Error(), "snapshot snap") {
		t.Fatalf("unexpected error: %v", err)
	}
	flat := filepath.Join(r.CacheDir(), "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.raw")
	if _, err := os.Stat(flat); err == nil {
		t.Fatal("CloneMedium flatten started for this snapshot")
	}
}

func TestVDIPayloadOffset(t *testing.T) {
	path := os.Getenv("QUARANTINE_TEST_VDI")
	if path == "" {
		t.Skip("set QUARANTINE_TEST_VDI to a raw disk image for this test")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Skip("no test VDI:", err)
	}
	defer f.Close()
	if _, err := ntfsPartitionReader(f); err != nil {
		t.Fatal(err)
	}
	data, size, err := ntfsReadFile(f, `C:\Users\Public\Quarantine\Install-QuarantineAgent.ps1`, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if size <= 0 || len(data) == 0 {
		t.Fatalf("empty file data size=%d len=%d", size, len(data))
	}
}
