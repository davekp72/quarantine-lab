//go:build no_ntfs

package disk

import (
	"fmt"
	"io"
)

func ntfsReadFile(r io.ReaderAt, guestPath string, maxBytes int64) ([]byte, int64, error) {
	return nil, 0, fmt.Errorf("NTFS reader not compiled (build without -tags no_ntfs)")
}

func ntfsListDir(r io.ReaderAt, guestPath string) ([]FileInfo, error) {
	return nil, fmt.Errorf("NTFS reader not compiled")
}
