package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDiffIndexesMergeJoin(t *testing.T) {
	dir := t.TempDir()
	fromPath := filepath.Join(dir, "from.jsonl.gz")
	toPath := filepath.Join(dir, "to.jsonl.gz")

	from := []IndexRecord{
		{K: `HKU:\.DEFAULT\System`, N: "Old", T: "REG_SZ", V: "1", H: ContentHash("REG_SZ", "1")},
		{K: `HKU:\.DEFAULT\System\SUS`, N: "SUS", T: "REG_SZ", V: "before", H: ContentHash("REG_SZ", "before")},
		{K: `HKLM:\SOFTWARE\A`, N: "X", T: "REG_DWORD", V: "0x1", H: ContentHash("REG_DWORD", "0x1")},
	}
	to := []IndexRecord{
		{K: `HKU:\.DEFAULT\System\SUS`, N: "SUS", T: "REG_SZ", V: "after", H: ContentHash("REG_SZ", "after")},
		{K: `HKLM:\SOFTWARE\A`, N: "X", T: "REG_DWORD", V: "0x1", H: ContentHash("REG_DWORD", "0x1")},
		{K: `HKLM:\SOFTWARE\B`, N: "New", T: "REG_SZ", V: "y", H: ContentHash("REG_SZ", "y")},
	}
	if err := WriteIndexSorted(fromPath, from); err != nil {
		t.Fatal(err)
	}
	if err := WriteIndexSorted(toPath, to); err != nil {
		t.Fatal(err)
	}

	d, err := DiffIndexes(fromPath, toPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Added) != 1 || d.Added[0].K != `HKLM:\SOFTWARE\B` {
		t.Fatalf("added=%+v", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0].N != "Old" {
		t.Fatalf("removed=%+v", d.Removed)
	}
	if len(d.Modified) != 1 || d.Modified[0].K != `HKU:\.DEFAULT\System\SUS` {
		t.Fatalf("modified=%+v", d.Modified)
	}
	if d.Modified[0].V0 != "before" || d.Modified[0].V1 != "after" {
		t.Fatalf("before/after=%v/%v", d.Modified[0].V0, d.Modified[0].V1)
	}
}

func TestWriteIndexJSONEscapes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "idx.jsonl.gz")
	// Non-ASCII / control bytes must not become Go \xNN escapes (invalid JSON).
	recs := []IndexRecord{
		{K: "HKLM:\\SOFTWARE\\\x01weird", N: "näme", T: "REG_SZ", H: "1", Size: 1},
	}
	if err := WriteIndexSorted(path, recs); err != nil {
		t.Fatal(err)
	}
	r, err := OpenIndex(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if !r.Next() {
		t.Fatal(r.Err())
	}
	got := r.Record()
	if got.K != recs[0].K || got.N != recs[0].N {
		t.Fatalf("got=%+v", got)
	}
}

func TestWriteIndexCompactRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "idx.jsonl.gz")
	recs := []IndexRecord{
		{K: `HKLM:\SOFTWARE\A`, N: "X", T: "REG_SZ", H: "abc", Size: 4},
		{K: `HKU:\.DEFAULT\System\SUS`, N: "SUS", T: "REG_SZ", H: "def", Size: 3, V: "SUS"},
	}
	if err := WriteIndexSorted(path, recs); err != nil {
		t.Fatal(err)
	}
	r, err := OpenIndex(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var got []IndexRecord
	for r.Next() {
		got = append(got, r.Record())
	}
	if r.Err() != nil {
		t.Fatal(r.Err())
	}
	if len(got) != 2 || got[0].K != recs[0].K || got[1].V != "SUS" || got[0].H != "abc" {
		t.Fatalf("got=%+v", got)
	}
}

func TestMergeSortedRecords(t *testing.T) {
	a := []IndexRecord{
		{K: `HKLM:\A`, N: "1", H: "a"},
		{K: `HKLM:\C`, N: "1", H: "c"},
	}
	b := []IndexRecord{
		{K: `HKLM:\B`, N: "1", H: "b"},
		{K: `HKLM:\D`, N: "1", H: "d"},
	}
	sortRecords(a)
	sortRecords(b)
	merged := mergeSortedRecords([][]IndexRecord{a, b})
	if len(merged) != 4 {
		t.Fatalf("len=%d", len(merged))
	}
	want := []string{`hklm:\a|1`, `hklm:\b|1`, `hklm:\c|1`, `hklm:\d|1`}
	for i, w := range want {
		if merged[i].SortKey() != w {
			t.Fatalf("i=%d got %s want %s", i, merged[i].SortKey(), w)
		}
	}
}

func TestBuildIndexFromLocalHivesParallel(t *testing.T) {
	dir := t.TempDir()
	hive := os.Getenv("QUARANTINE_DEFAULT_HIVE")
	if hive == "" {
		t.Skip("set QUARANTINE_DEFAULT_HIVE for parallel local build smoke")
	}
	files := []LocalHiveFile{
		{LocalPath: hive, GuestPath: "DEFAULT", Prefix: `HKU:\.DEFAULT`},
		{LocalPath: hive, GuestPath: "DEFAULT2", Prefix: `HKU:\.DEFAULT2`},
	}
	indexPath := filepath.Join(dir, "idx.jsonl.gz")
	metaPath := filepath.Join(dir, "meta.json")
	meta, err := BuildIndexFromLocalHives("test", indexPath, metaPath, files)
	if err != nil {
		t.Fatal(err)
	}
	if meta.EntryCount == 0 {
		t.Fatal("expected entries")
	}
	r, err := OpenIndex(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var prev string
	n := 0
	for r.Next() {
		k := r.Record().SortKey()
		if prev != "" && k < prev {
			t.Fatalf("unsorted: %s then %s", prev, k)
		}
		prev = k
		n++
	}
	if n != meta.EntryCount {
		t.Fatalf("read %d meta %d", n, meta.EntryCount)
	}
}

func TestBuildIndexCleanSessionTiming(t *testing.T) {
	dir := os.Getenv("QUARANTINE_TEST_HIVES")
	if dir == "" {
		t.Skip("set QUARANTINE_TEST_HIVES to a hive dump directory")
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]string{
		"SOFTWARE": `HKLM:\SOFTWARE`,
		"SYSTEM":   `HKLM:\SYSTEM`,
		"DEFAULT":  `HKU:\.DEFAULT`,
		"SAM":      `HKLM:\SAM`,
		"SECURITY": `HKLM:\SECURITY`,
	}
	var files []LocalHiveFile
	for _, e := range ents {
		if e.IsDir() || e.Name() == "manifest.json" {
			continue
		}
		prefix := known[e.Name()]
		if prefix == "" && strings.HasPrefix(e.Name(), "NTUSER_") {
			prefix = `HKU:\` + strings.TrimPrefix(e.Name(), "NTUSER_")
		}
		if prefix == "" {
			continue
		}
		files = append(files, LocalHiveFile{
			LocalPath: filepath.Join(dir, e.Name()),
			GuestPath: e.Name(),
			Prefix:    prefix,
		})
	}
	if len(files) == 0 {
		t.Skip("no hive files")
	}
	out := t.TempDir()
	start := time.Now()
	meta, err := BuildIndexFromLocalHives("CleanSession", filepath.Join(out, "idx.jsonl.gz"), filepath.Join(out, "meta.json"), files)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("full index: %d entries from %d hives in %s", meta.EntryCount, len(files), time.Since(start).Round(time.Millisecond))
	if meta.EntryCount < 10000 {
		t.Fatalf("expected large index, got %d", meta.EntryCount)
	}
}

func TestWalkHiveSOFTWARETiming(t *testing.T) {
	hive := os.Getenv("QUARANTINE_SOFTWARE_HIVE")
	if hive == "" {
		t.Skip("set QUARANTINE_SOFTWARE_HIVE to a SOFTWARE hive path")
	}
	if st, err := os.Stat(hive); err != nil || st.IsDir() {
		t.Skip("SOFTWARE hive not found")
	}
	start := time.Now()
	var records []IndexRecord
	n, err := WalkHiveFile(hive, `HKLM:\SOFTWARE`, &records)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("SOFTWARE walk: %d entries in %s (%s)", n, time.Since(start).Round(time.Millisecond), hive)
	if n < 1000 {
		t.Fatalf("expected a large SOFTWARE hive, got %d", n)
	}
}

func TestWalkHiveDEFAULTSmoke(t *testing.T) {
	hive := os.Getenv("QUARANTINE_DEFAULT_HIVE")
	if hive == "" {
		t.Skip("set QUARANTINE_DEFAULT_HIVE to a DEFAULT hive path for smoke")
	}
	var records []IndexRecord
	n, err := WalkHiveFile(hive, `HKU:\.DEFAULT`, &records)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("expected entries")
	}
	found := false
	for _, r := range records {
		if r.K == `HKU:\.DEFAULT\System\SUS` && r.N == "SUS" {
			found = true
			break
		}
	}
	if !found {
		t.Logf("SUS not present in hive (%d entries) — ok if not planted", n)
	}
}
