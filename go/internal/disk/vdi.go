package disk

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	vdiSignature     = 0xbeda107f
	vdiTypeDynamic   = 1
	vdiTypeFixed     = 2
	vdiTypeUndo      = 3
	vdiTypeDiff      = 4
	vdiBlockFree     = 0xffffffff
	vdiBlockZero     = 0xfffffffe
	vdiVersion1_1    = 0x00010001
	maxBlockMapBytes = 64 << 20
)

var errNotVDI = errors.New("not a VDI image")

// vdiHeader is the VirtualBox 1.1 / 1.1+ fields we need for sector mapping.
type vdiHeader struct {
	Type       uint32
	OffBlocks  uint32
	OffData    uint32
	DiskSize   uint64
	BlockSize  uint32
	BlockExtra uint32
	Blocks     uint32
}

type vdiImage struct {
	r      io.ReaderAt
	hdr    vdiHeader
	bmap   []uint32
	parent *vdiImage
}

// snapshotView is a linear virtual disk (VDI chain or RAW) plus open files.
type snapshotView struct {
	r     io.ReaderAt
	files []*os.File
}

func (v *snapshotView) ReadAt(p []byte, off int64) (int, error) {
	return v.r.ReadAt(p, off)
}

func (v *snapshotView) Close() error {
	if v == nil {
		return nil
	}
	var first error
	for _, f := range v.files {
		if f == nil {
			continue
		}
		if err := f.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func parseVDIHeader(r io.ReaderAt) (*vdiHeader, error) {
	var raw [0x190]byte
	n, err := r.ReadAt(raw[:], 0)
	if n < 0x44 {
		return nil, errNotVDI
	}
	if binary.LittleEndian.Uint32(raw[0x40:0x44]) != vdiSignature {
		return nil, errNotVDI
	}
	if err != nil && err != io.EOF {
		return nil, err
	}
	if n < 0x184 {
		return nil, fmt.Errorf("truncated VDI header")
	}
	version := binary.LittleEndian.Uint32(raw[0x44:0x48])
	if version>>16 != 1 {
		return nil, fmt.Errorf("unsupported VDI version 0x%08x", version)
	}
	hdr := &vdiHeader{
		Type:       binary.LittleEndian.Uint32(raw[0x4c:0x50]),
		OffBlocks:  binary.LittleEndian.Uint32(raw[0x154:0x158]),
		OffData:    binary.LittleEndian.Uint32(raw[0x158:0x15c]),
		DiskSize:   binary.LittleEndian.Uint64(raw[0x170:0x178]),
		BlockSize:  binary.LittleEndian.Uint32(raw[0x178:0x17c]),
		BlockExtra: binary.LittleEndian.Uint32(raw[0x17c:0x180]),
		Blocks:     binary.LittleEndian.Uint32(raw[0x180:0x184]),
	}
	if hdr.Type < vdiTypeDynamic || hdr.Type > vdiTypeDiff {
		return nil, fmt.Errorf("unsupported VDI type %d", hdr.Type)
	}
	if hdr.BlockSize < 512 || hdr.BlockSize&(hdr.BlockSize-1) != 0 {
		return nil, fmt.Errorf("invalid VDI block size %d", hdr.BlockSize)
	}
	if hdr.Blocks == 0 || hdr.DiskSize == 0 {
		return nil, fmt.Errorf("invalid VDI geometry blocks=%d size=%d", hdr.Blocks, hdr.DiskSize)
	}
	if hdr.OffBlocks == 0 || hdr.OffData == 0 {
		return nil, fmt.Errorf("invalid VDI offsets blocks=%d data=%d", hdr.OffBlocks, hdr.OffData)
	}
	mapBytes := uint64(hdr.Blocks) * 4
	if mapBytes > maxBlockMapBytes {
		return nil, fmt.Errorf("VDI block map too large (%d bytes)", mapBytes)
	}
	return hdr, nil
}

func loadVDIImage(r io.ReaderAt) (*vdiImage, error) {
	hdr, err := parseVDIHeader(r)
	if err != nil {
		return nil, err
	}
	img := &vdiImage{r: r, hdr: *hdr}
	if err := img.loadBlockMap(); err != nil {
		return nil, err
	}
	return img, nil
}

func (img *vdiImage) loadBlockMap() error {
	n := int(img.hdr.Blocks)
	raw := make([]byte, n*4)
	if err := readFullAt(img.r, raw, int64(img.hdr.OffBlocks)); err != nil {
		return fmt.Errorf("read VDI block map: %w", err)
	}
	img.bmap = make([]uint32, n)
	for i := 0; i < n; i++ {
		img.bmap[i] = binary.LittleEndian.Uint32(raw[i*4 : i*4+4])
	}
	return nil
}

func (img *vdiImage) physicalOffset(blockIndex, into int64) int64 {
	be := img.bmap[blockIndex]
	stride := int64(img.hdr.BlockSize) + int64(img.hdr.BlockExtra)
	return int64(img.hdr.OffData) + int64(be)*stride + int64(img.hdr.BlockExtra) + into
}

func (img *vdiImage) ReadAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	size := int64(img.hdr.DiskSize)
	if off >= size {
		return 0, io.EOF
	}
	done := 0
	for done < len(p) {
		cur := off + int64(done)
		if cur >= size {
			if done == 0 {
				return 0, io.EOF
			}
			return done, io.EOF
		}
		n := len(p) - done
		if remain := size - cur; int64(n) > remain {
			n = int(remain)
		}
		bs := int64(img.hdr.BlockSize)
		idx := cur / bs
		into := cur % bs
		if chunk := bs - into; int64(n) > chunk {
			n = int(chunk)
		}
		if idx < 0 || idx >= int64(len(img.bmap)) {
			clear(p[done : done+n])
			done += n
			continue
		}
		be := img.bmap[idx]
		switch {
		case be == vdiBlockZero:
			clear(p[done : done+n])
		case be == vdiBlockFree || be >= vdiBlockZero:
			if img.parent != nil {
				nn, err := img.parent.ReadAt(p[done:done+n], cur)
				if nn < n {
					clear(p[done+nn : done+n])
				}
				if err != nil && err != io.EOF && nn < n {
					return done + nn, err
				}
			} else {
				clear(p[done : done+n])
			}
		default:
			if err := readFullAt(img.r, p[done:done+n], img.physicalOffset(idx, into)); err != nil {
				return done, err
			}
		}
		done += n
	}
	return done, nil
}

func readFullAt(r io.ReaderAt, p []byte, off int64) error {
	got := 0
	for got < len(p) {
		n, err := r.ReadAt(p[got:], off+int64(got))
		got += n
		if err != nil {
			if err == io.EOF && got == len(p) {
				return nil
			}
			if err == io.EOF {
				return io.ErrUnexpectedEOF
			}
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

// openVDIChain opens leaf-first VDI paths as one virtual disk. A single RAW
// (or non-VDI) file is accepted for flatten-cache fallback.
func openVDIChain(paths []string) (*snapshotView, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("empty VDI chain")
	}
	files := make([]*os.File, 0, len(paths))
	closeAll := func() {
		for _, f := range files {
			_ = f.Close()
		}
	}
	var imgs []*vdiImage
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("open %s: %w", p, err)
		}
		files = append(files, f)
		img, err := loadVDIImage(f)
		if err != nil {
			if errors.Is(err, errNotVDI) {
				if len(paths) == 1 {
					return &snapshotView{r: f, files: files}, nil
				}
				closeAll()
				return nil, fmt.Errorf("%s: not a VDI (needed for differencing chain)", p)
			}
			closeAll()
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		imgs = append(imgs, img)
	}
	for i := 0; i < len(imgs)-1; i++ {
		imgs[i].parent = imgs[i+1]
	}
	return &snapshotView{r: imgs[0], files: files}, nil
}

// vdiPayloadOffset returns the byte offset in a VDI file where disk sectors begin.
// Returns 0 for raw disk images (VDI/HDD/VDK without Oracle header).
// Used only for linear flatten caches; dynamic/differencing images need openVDIChain.
func vdiPayloadOffset(r io.ReaderAt) (int64, error) {
	var hdr [0x200]byte
	if _, err := r.ReadAt(hdr[:], 0); err != nil {
		return 0, err
	}
	if !bytes.HasPrefix(hdr[:], []byte("<<<<<<< Oracle VM VirtualBox")) &&
		binary.LittleEndian.Uint32(hdr[0x40:0x44]) != vdiSignature {
		return 0, nil
	}
	off := int64(binary.LittleEndian.Uint32(hdr[0x50:0x54]))
	imgType := binary.LittleEndian.Uint32(hdr[0x4c:0x50])
	hdrSize := binary.LittleEndian.Uint32(hdr[0x48:0x4c])
	if off == 0 {
		if imgType == 1 {
			// Dynamic VDI: MBR/GPT at 2 MiB; only valid for linear fixed clones.
			off = 0x200000
		} else if hdrSize >= 0x200 {
			off = int64(hdrSize)
		}
	}
	if off < 0x200 && imgType != 1 {
		return 0, fmt.Errorf("invalid VDI payload offset %d", off)
	}
	return off, nil
}

type offsetReaderAt struct {
	r      io.ReaderAt
	offset int64
}

func (o offsetReaderAt) ReadAt(p []byte, off int64) (int, error) {
	return o.r.ReadAt(p, off+o.offset)
}

// diskView returns a ReaderAt positioned at the virtual disk payload (skips VDI header).
func diskView(r io.ReaderAt) (io.ReaderAt, int64, error) {
	payload, err := vdiPayloadOffset(r)
	if err != nil {
		return nil, 0, err
	}
	if payload == 0 {
		return r, 0, nil
	}
	return offsetReaderAt{r: r, offset: payload}, payload, nil
}

// ntfsPartitionReader returns a reader positioned at the NTFS boot sector.
// go-ntfs expects GetNTFSContext(reader, 0) with the boot sector at reader offset 0.
func ntfsPartitionReader(r io.ReaderAt) (io.ReaderAt, error) {
	disk, payload, err := diskView(r)
	if err != nil {
		return nil, err
	}
	rel, err := findNTFSOffset(disk)
	if err != nil {
		return nil, err
	}
	return offsetReaderAt{r: r, offset: payload + rel}, nil
}
