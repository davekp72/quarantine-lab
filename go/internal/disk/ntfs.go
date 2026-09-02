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
		maxBytes = 10 * 1024 * 1024
	}
	offset, err := findNTFSOffset(r)
	if err != nil {
		return nil, 0, err
	}
	ctx, err := ntfs.GetNTFSContext(r, offset)
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
	// Common Windows VDI layouts: try GPT ESP skip then NTFS, then MBR.
	candidates := []int64{0, 512, 1024 * 1024, 2048 * 512}
	for _, off := range candidates {
		if ok, _ := isNTFSBoot(r, off); ok {
			return off, nil
		}
	}
	// Scan first 4MB for NTFS OEM ID
	var buf [512]byte
	for off := int64(0); off < 4*1024*1024; off += 512 {
		if _, err := r.ReadAt(buf[:], off); err != nil {
			break
		}
		if bytes.Equal(buf[3:11], []byte("NTFS    ")) {
			return off, nil
		}
	}
	return 0, fmt.Errorf("NTFS partition not found in disk image")
}

func isNTFSBoot(r io.ReaderAt, offset int64) (bool, error) {
	var buf [512]byte
	if _, err := r.ReadAt(buf[:], offset); err != nil {
		return false, err
	}
	return bytes.Equal(buf[3:11], []byte("NTFS    ")), nil
}

func ntfsListDir(r io.ReaderAt, guestPath string) ([]FileInfo, error) {
	offset, err := findNTFSOffset(r)
	if err != nil {
		return nil, err
	}
	ctx, err := ntfs.GetNTFSContext(r, offset)
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

// readPartitionStart reads MBR partition LBA if present.
func readPartitionStart(r io.ReaderAt) int64 {
	var mbr [512]byte
	if _, err := r.ReadAt(mbr[:], 0); err != nil {
		return 0
	}
	if binary.LittleEndian.Uint16(mbr[510:512]) != 0xAA55 {
		return 0
	}
	start := binary.LittleEndian.Uint32(mbr[446+8 : 446+12])
	return int64(start) * 512
}
