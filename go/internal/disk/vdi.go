package disk

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// vdiPayloadOffset returns the byte offset in a VDI file where disk sectors begin.
// Returns 0 for raw disk images (VDI/HDD/VDK without Oracle header).
func vdiPayloadOffset(r io.ReaderAt) (int64, error) {
	var hdr [0x200]byte
	if _, err := r.ReadAt(hdr[:], 0); err != nil {
		return 0, err
	}
	if !bytes.HasPrefix(hdr[:], []byte("<<<<<<< Oracle VM VirtualBox")) {
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
