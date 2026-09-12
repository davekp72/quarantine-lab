package unattend

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/diskfs/go-diskfs"
	"github.com/diskfs/go-diskfs/disk"
	"github.com/diskfs/go-diskfs/filesystem"
)

const floppySize = 1440 * 1024 // 1.44 MiB
const floppyMaxFileBytes = 400 * 1024

// WriteFloppyImage creates a 1.44MB FAT floppy image with the given files.
// keys are paths inside the image (forward slashes), values are host file paths.
func WriteFloppyImage(dest string, files map[string]string) error {
	if len(files) == 0 {
		return fmt.Errorf("no files to pack into floppy")
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	_ = os.Remove(dest)

	d, err := diskfs.Create(dest, floppySize, diskfs.SectorSize512)
	if err != nil {
		return fmt.Errorf("create floppy image: %w", err)
	}
	defer func() { _ = d.Close() }()

	// Partition 0 = whole-disk (super-floppy). diskfs picks FAT12 for this size.
	fs, err := d.CreateFilesystem(disk.FilesystemSpec{
		Partition:   0,
		FSType:      filesystem.TypeFat32,
		VolumeLabel: "UNATTEND",
	})
	if err != nil {
		return fmt.Errorf("create FAT filesystem on floppy: %w", err)
	}
	defer func() { _ = fs.Close() }()

	for imgPath, hostPath := range files {
		imgPath = strings.TrimPrefix(filepath.ToSlash(imgPath), "/")
		if imgPath == "" {
			return fmt.Errorf("empty image path for %s", hostPath)
		}
		raw, err := os.ReadFile(hostPath)
		if err != nil {
			return fmt.Errorf("read %s: %w", hostPath, err)
		}
		dir := filepath.ToSlash(filepath.Dir(imgPath))
		if dir != "." && dir != "" {
			if err := mkdirAllFS(fs, dir); err != nil {
				return fmt.Errorf("mkdir %s: %w", dir, err)
			}
		}
		f, err := fs.OpenFile("/"+imgPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC)
		if err != nil {
			return fmt.Errorf("create %s in floppy: %w", imgPath, err)
		}
		if _, err := f.Write(raw); err != nil {
			_ = f.Close()
			return fmt.Errorf("write %s: %w", imgPath, err)
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	return nil
}

func mkdirAllFS(fs filesystem.FileSystem, dir string) error {
	dir = strings.Trim(filepath.ToSlash(dir), "/")
	if dir == "" || dir == "." {
		return nil
	}
	parts := strings.Split(dir, "/")
	cur := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		if cur == "" {
			cur = p
		} else {
			cur = cur + "/" + p
		}
		_ = fs.Mkdir("/" + cur) // ignore already-exists
	}
	return nil
}

// WriteFloppyFromDir packs every regular file under root into a floppy image,
// preserving relative paths.
func WriteFloppyFromDir(dest, root string) error {
	files := map[string]string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relSlash := filepath.ToSlash(rel)
		if skipFloppyFile(relSlash, info) {
			return nil
		}
		files[relSlash] = path
		return nil
	})
	if err != nil {
		return err
	}
	return WriteFloppyImage(dest, files)
}

func skipFloppyFile(rel string, info os.FileInfo) bool {
	if info.Size() > floppyMaxFileBytes {
		return true
	}
	if strings.EqualFold(filepath.Ext(rel), ".exe") {
		return true
	}
	lower := strings.ToLower(rel)
	return strings.Contains(lower, "agent-staging/") || strings.Contains(lower, "sysmon/")
}

func copyFile(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
