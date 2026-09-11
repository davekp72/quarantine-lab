package disk

import (
	"os"
	"testing"
)

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
