package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGuestCopyDest(t *testing.T) {
	dir := t.TempDir()
	host := filepath.Join(dir, "sample.txt")
	if err := os.WriteFile(host, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	abs, dest, destDir, err := guestCopyDest(host, "", `C:\Users\Public\Quarantine`)
	if err != nil {
		t.Fatal(err)
	}
	if abs != host {
		t.Fatalf("abs %s", abs)
	}
	if dest != `C:\Users\Public\Quarantine\sample.txt` || destDir != `C:\Users\Public\Quarantine` {
		t.Fatalf("dest %s dir %s", dest, destDir)
	}
	if _, _, _, err := guestCopyDest(dir, "", ""); err == nil {
		t.Fatal("expected directory error")
	}
}
