//go:build !no_ntfs

package disk

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	ntfs "www.velocidex.com/golang/go-ntfs/parser"
)

func ntfsReadFile(r io.ReaderAt, guestPath string, maxBytes int64) ([]byte, int64, error) {
	if maxBytes <= 0 {
		maxBytes = 512 * 1024 * 1024
	}
	part, err := ntfsPartitionReader(r)
	if err != nil {
		return nil, 0, err
	}
	ctx, err := ntfs.GetNTFSContext(part, 0)
	if err != nil {
		return nil, 0, err
	}
	defer ctx.Close()

	rel := guestToNTFSPath(guestPath)
	reader, err := ntfs.GetDataForPath(ctx, rel)
	if err != nil {
		return nil, 0, err
	}
	size := ntfs.RangeSize(reader)
	if size > maxBytes {
		return nil, size, fmt.Errorf("file too large (%d bytes, max %d)", size, maxBytes)
	}
	if size <= 0 {
		return []byte{}, 0, nil
	}
	buf := make([]byte, size)
	n, err := reader.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return nil, size, err
	}
	return buf[:n], size, nil
}

func guestToNTFSPath(guestPath string) string {
	p := normalizeGuestPath(guestPath)
	p = trimSlash(p)
	if len(p) >= 2 && p[1] == ':' {
		p = p[2:]
	}
	return trimSlash(p)
}

func findNTFSOffset(r io.ReaderAt) (int64, error) {
	for _, start := range mbrPartitionStarts(r) {
		if ok, _ := isNTFSBoot(r, start); ok {
			return start, nil
		}
	}
	if off := findGPTNTFSOffset(r); off >= 0 {
		return off, nil
	}
	// Common offsets: ESP skip, Windows default partition start.
	candidates := []int64{0, 512, 1024 * 1024, 2048 * 512}
	for _, off := range candidates {
		if ok, _ := isNTFSBoot(r, off); ok {
			return off, nil
		}
	}
	var buf [512]byte
	for off := int64(0); off < 64*1024*1024; off += 512 {
		if _, err := r.ReadAt(buf[:], off); err != nil {
			break
		}
		if bytes.Equal(buf[3:11], []byte("NTFS    ")) {
			return off, nil
		}
	}
	return 0, fmt.Errorf("NTFS partition not found in disk image")
}

func mbrPartitionStarts(r io.ReaderAt) []int64 {
	var mbr [512]byte
	if _, err := r.ReadAt(mbr[:], 0); err != nil {
		return nil
	}
	if binary.LittleEndian.Uint16(mbr[510:512]) != 0xAA55 {
		return nil
	}
	var starts []int64
	for i := 0; i < 4; i++ {
		base := 446 + i*16
		start := binary.LittleEndian.Uint32(mbr[base+8 : base+12])
		if start > 0 {
			starts = append(starts, int64(start)*512)
		}
	}
	return starts
}

func findGPTNTFSOffset(r io.ReaderAt) int64 {
	var mbr [512]byte
	if _, err := r.ReadAt(mbr[:], 0); err != nil {
		return -1
	}
	if binary.LittleEndian.Uint16(mbr[510:512]) != 0xAA55 || mbr[450] != 0xEE {
		return -1
	}
	var gptHdr [512]byte
	if _, err := r.ReadAt(gptHdr[:], 512); err != nil {
		return -1
	}
	if !bytes.Equal(gptHdr[0:8], []byte("EFI PART")) {
		return -1
	}
	entryLBA := binary.LittleEndian.Uint64(gptHdr[72:80])
	entryCount := binary.LittleEndian.Uint32(gptHdr[80:84])
	entrySize := binary.LittleEndian.Uint32(gptHdr[84:88])
	if entryLBA == 0 || entryCount == 0 || entrySize < 128 {
		return -1
	}
	if entryCount > 128 {
		entryCount = 128
	}
	entryOff := int64(entryLBA) * 512
	buf := make([]byte, int(entrySize))
	var bestOff int64 = -1
	var bestSize uint64
	for i := uint32(0); i < entryCount; i++ {
		off := entryOff + int64(i)*int64(entrySize)
		if _, err := r.ReadAt(buf, off); err != nil {
			break
		}
		if isZeroGUID(buf[0:16]) {
			continue
		}
		firstLBA := binary.LittleEndian.Uint64(buf[32:40])
		lastLBA := binary.LittleEndian.Uint64(buf[40:48])
		if firstLBA == 0 || lastLBA < firstLBA {
			continue
		}
		partOff := int64(firstLBA) * 512
		if ok, _ := isNTFSBoot(r, partOff); !ok {
			continue
		}
		size := lastLBA - firstLBA + 1
		if size > bestSize {
			bestSize = size
			bestOff = partOff
		}
	}
	return bestOff
}

func isZeroGUID(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func isNTFSBoot(r io.ReaderAt, offset int64) (bool, error) {
	var buf [512]byte
	if _, err := r.ReadAt(buf[:], offset); err != nil {
		return false, err
	}
	return bytes.Equal(buf[3:11], []byte("NTFS    ")), nil
}

func ntfsListDir(r io.ReaderAt, guestPath string) ([]FileInfo, error) {
	part, err := ntfsPartitionReader(r)
	if err != nil {
		return nil, err
	}
	ctx, err := ntfs.GetNTFSContext(part, 0)
	if err != nil {
		return nil, err
	}
	defer ctx.Close()

	root, err := ctx.GetMFT(5)
	if err != nil {
		return nil, err
	}
	rel := guestToNTFSPath(guestPath)
	if rel == "" {
		rel = "."
	}
	dir, err := root.Open(ctx, rel)
	if err != nil {
		return nil, err
	}
	entries := ntfs.ListDir(ctx, dir)
	out := make([]FileInfo, 0, len(entries))
	for _, e := range entries {
		name := e.Name
		if name == "" {
			continue
		}
		full := guestPath
		if !stringsHasSuffix(full, `\`) && full != "" {
			full += `\`
		}
		if rel == "." || rel == "" {
			full = normalizeGuestPath(name)
		} else {
			full = normalizeGuestPath(guestPath + `\` + name)
		}
		out = append(out, FileInfo{
			Path:        full,
			Size:        e.Size,
			IsDirectory: e.IsDir,
		})
	}
	return out, nil
}

func stringsHasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
