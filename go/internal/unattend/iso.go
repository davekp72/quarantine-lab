package unattend

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/diskfs/go-diskfs"
	"github.com/diskfs/go-diskfs/disk"
	"github.com/diskfs/go-diskfs/filesystem"
	"github.com/diskfs/go-diskfs/filesystem/iso9660"
)

// WriteISOFromDir packs mediaDir into a Joliet ISO9660 image (EFI-friendly unattend DVD).
func WriteISOFromDir(dest, root string) error {
	var total int64
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	if err != nil {
		return err
	}
	// ISO needs headroom for structures; keep at least 8 MiB.
	size := total + 4*1024*1024
	if size < 8*1024*1024 {
		size = 8 * 1024 * 1024
	}
	// Round up to 2048-byte sectors.
	const block = int64(2048)
	size = ((size + block - 1) / block) * block

	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	_ = os.Remove(dest)

	d, err := diskfs.Create(dest, size, diskfs.SectorSize(2048))
	if err != nil {
		return fmt.Errorf("create ISO image: %w", err)
	}
	defer func() { _ = d.Close() }()

	fs, err := d.CreateFilesystem(disk.FilesystemSpec{
		Partition:   0,
		FSType:      filesystem.TypeISO9660,
		VolumeLabel: "UNATTEND",
	})
	if err != nil {
		return fmt.Errorf("create ISO9660 filesystem: %w", err)
	}

	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		imgPath := "/" + rel
		if info.IsDir() {
			return fs.Mkdir(imgPath)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		dir := filepath.ToSlash(filepath.Dir(rel))
		if dir != "." && dir != "" {
			_ = mkdirAllFS(fs, dir)
		}
		f, err := fs.OpenFile(imgPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC)
		if err != nil {
			return fmt.Errorf("create %s in ISO: %w", imgPath, err)
		}
		if _, err := f.Write(raw); err != nil {
			_ = f.Close()
			return err
		}
		return f.Close()
	})
	if err != nil {
		_ = fs.Close()
		return err
	}

	isoFS, ok := fs.(*iso9660.FileSystem)
	if !ok {
		_ = fs.Close()
		return fmt.Errorf("unexpected filesystem type %T", fs)
	}
	if err := isoFS.Finalize(iso9660.FinalizeOptions{
		VolumeIdentifier: "UNATTEND",
		Joliet:           true,
		RockRidge:        true,
		DeepDirectories:  true,
	}); err != nil {
		return fmt.Errorf("finalize ISO: %w", err)
	}
	return nil
}
