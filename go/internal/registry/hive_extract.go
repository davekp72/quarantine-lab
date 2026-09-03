package registry

import (
	"container/heap"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// HiveSpec describes a guest hive to extract and its registry prefix.
type HiveSpec struct {
	GuestPath string
	Prefix    string
}

var systemHives = []HiveSpec{
	{`C:\Windows\System32\config\SOFTWARE`, `HKLM:\SOFTWARE`},
	{`C:\Windows\System32\config\SYSTEM`, `HKLM:\SYSTEM`},
	{`C:\Windows\System32\config\DEFAULT`, `HKU:\.DEFAULT`},
	{`C:\Windows\System32\config\SAM`, `HKLM:\SAM`},
	{`C:\Windows\System32\config\SECURITY`, `HKLM:\SECURITY`},
}

// DiskExtractor extracts guest files from a snapshot disk.
type DiskExtractor interface {
	ExtractFile(snapshotName, guestPath, destPath string) (int64, error)
}

// LocalHiveFile is a hive already on the host filesystem.
type LocalHiveFile struct {
	LocalPath string
	GuestPath string
	Prefix    string
}

type hiveWalkResult struct {
	meta    HiveMeta
	records []IndexRecord // sorted by SortKey
}

// BuildIndexFromLocalHives walks already-copied hive files in parallel and writes sorted index + meta.
func BuildIndexFromLocalHives(snapshotName, indexPath, metaPath string, files []LocalHiveFile) (*IndexMeta, error) {
	meta := &IndexMeta{
		Engine:   "hive",
		Snapshot: snapshotName,
		BuiltAt:  time.Now().UTC().Format(time.RFC3339),
		Digests:  map[string]string{},
	}
	meta.Warnings = append(meta.Warnings, "source: live-reg-save")

	results := walkLocalHivesParallel(files)
	chunks := make([][]IndexRecord, 0, len(results))
	for _, r := range results {
		meta.Hives = append(meta.Hives, r.meta)
		if r.meta.Error != "" {
			meta.Warnings = append(meta.Warnings, fmt.Sprintf("%s: %s", r.meta.GuestPath, r.meta.Error))
			continue
		}
		if r.meta.SHA256 != "" {
			meta.Digests[r.meta.GuestPath] = r.meta.SHA256
		}
		if len(r.records) > 0 {
			chunks = append(chunks, r.records)
		}
	}

	records := mergeSortedRecords(chunks)
	aliasCurrentControlSet(&records)
	sortRecords(records) // CCS aliases appended unsorted

	if err := WriteIndexSorted(indexPath, records); err != nil {
		return nil, err
	}
	meta.EntryCount = len(records)
	if err := WriteIndexMeta(metaPath, *meta); err != nil {
		return nil, err
	}
	return meta, nil
}

// BuildIndexFromDisk extracts hives from the snapshot disk (walks in parallel) and writes sorted index + meta.
func BuildIndexFromDisk(dx DiskExtractor, snapshotName, indexPath, metaPath, workDir string) (*IndexMeta, error) {
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return nil, err
	}
	meta := &IndexMeta{
		Engine:   "hive",
		Snapshot: snapshotName,
		BuiltAt:  time.Now().UTC().Format(time.RFC3339),
		Digests:  map[string]string{},
	}

	sysResults := extractAndWalkParallel(dx, snapshotName, workDir, systemHives)
	var sysChunks [][]IndexRecord
	for _, r := range sysResults {
		meta.Hives = append(meta.Hives, r.meta)
		if r.meta.Error != "" {
			meta.Warnings = append(meta.Warnings, fmt.Sprintf("%s: %s", r.meta.GuestPath, r.meta.Error))
			continue
		}
		if r.meta.SHA256 != "" {
			meta.Digests[r.meta.GuestPath] = r.meta.SHA256
		}
		if len(r.records) > 0 {
			sysChunks = append(sysChunks, r.records)
		}
	}
	sysRecords := mergeSortedRecords(sysChunks)

	userHives := discoverUserHives(&sysRecords)
	userResults := extractAndWalkParallel(dx, snapshotName, workDir, userHives)
	var userChunks [][]IndexRecord
	for _, r := range userResults {
		meta.Hives = append(meta.Hives, r.meta)
		if r.meta.Error != "" {
			meta.Warnings = append(meta.Warnings, fmt.Sprintf("%s: %s", r.meta.GuestPath, r.meta.Error))
			continue
		}
		if r.meta.SHA256 != "" {
			meta.Digests[r.meta.GuestPath] = r.meta.SHA256
		}
		if len(r.records) > 0 {
			userChunks = append(userChunks, r.records)
		}
	}

	records := mergeSortedRecords(append(sysChunks, userChunks...))
	aliasCurrentControlSet(&records)
	sortRecords(records)

	if err := WriteIndexSorted(indexPath, records); err != nil {
		return nil, err
	}
	meta.EntryCount = len(records)
	if err := WriteIndexMeta(metaPath, *meta); err != nil {
		return nil, err
	}
	return meta, nil
}

func walkLocalHivesParallel(files []LocalHiveFile) []hiveWalkResult {
	out := make([]hiveWalkResult, len(files))
	if len(files) == 0 {
		return out
	}
	workers := runtime.GOMAXPROCS(0)
	if workers < 2 {
		workers = 2
	}
	if workers > len(files) {
		workers = len(files)
	}
	ch := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range ch {
				out[i] = walkOneLocalHive(files[i])
			}
		}()
	}
	for i := range files {
		ch <- i
	}
	close(ch)
	wg.Wait()
	return out
}

func walkOneLocalHive(f LocalHiveFile) hiveWalkResult {
	hm := HiveMeta{GuestPath: f.GuestPath, Prefix: f.Prefix}
	st, err := os.Stat(f.LocalPath)
	if err != nil {
		hm.Error = err.Error()
		return hiveWalkResult{meta: hm}
	}
	hm.Size = st.Size()

	var recs []IndexRecord
	n, err := WalkHiveFile(f.LocalPath, f.Prefix, &recs)
	if err != nil {
		hm.Error = err.Error()
		return hiveWalkResult{meta: hm}
	}
	hm.Entries = n
	// Hash after walk so the OS page cache from the parse is reused (no parallel double-read).
	if raw, rerr := os.ReadFile(f.LocalPath); rerr == nil {
		sum := sha256.Sum256(raw)
		hm.SHA256 = hex.EncodeToString(sum[:])
	}
	sortRecords(recs)
	return hiveWalkResult{meta: hm, records: recs}
}

func extractAndWalkParallel(dx DiskExtractor, snapshotName, workDir string, specs []HiveSpec) []hiveWalkResult {
	out := make([]hiveWalkResult, len(specs))
	if len(specs) == 0 {
		return out
	}
	workers := runtime.GOMAXPROCS(0)
	if workers < 2 {
		workers = 2
	}
	if workers > len(specs) {
		workers = len(specs)
	}
	ch := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range ch {
				out[i] = extractAndWalkOne(dx, snapshotName, workDir, specs[i])
			}
		}()
	}
	for i := range specs {
		ch <- i
	}
	close(ch)
	wg.Wait()
	return out
}

func extractAndWalkOne(dx DiskExtractor, snapshotName, workDir string, spec HiveSpec) hiveWalkResult {
	hm := HiveMeta{GuestPath: spec.GuestPath, Prefix: spec.Prefix}
	local := filepath.Join(workDir, sanitizeName(strings.ReplaceAll(spec.GuestPath, `\`, `_`)))
	size, err := dx.ExtractFile(snapshotName, spec.GuestPath, local)
	if err != nil {
		hm.Error = err.Error()
		return hiveWalkResult{meta: hm}
	}
	hm.Size = size

	var recs []IndexRecord
	n, err := WalkHiveFile(local, spec.Prefix, &recs)
	if err != nil {
		hm.Error = err.Error()
		return hiveWalkResult{meta: hm}
	}
	hm.Entries = n
	if raw, rerr := os.ReadFile(local); rerr == nil {
		sum := sha256.Sum256(raw)
		hm.SHA256 = hex.EncodeToString(sum[:])
	}
	sortRecords(recs)
	return hiveWalkResult{meta: hm, records: recs}
}

func sortRecords(records []IndexRecord) {
	sort.Slice(records, func(i, j int) bool {
		return records[i].SortKey() < records[j].SortKey()
	})
}

// mergeSortedRecords k-way merges already-sorted record slices.
func mergeSortedRecords(chunks [][]IndexRecord) []IndexRecord {
	chunks = filterNonEmpty(chunks)
	if len(chunks) == 0 {
		return nil
	}
	if len(chunks) == 1 {
		out := make([]IndexRecord, len(chunks[0]))
		copy(out, chunks[0])
		return out
	}
	h := make(recHeap, 0, len(chunks))
	for i, c := range chunks {
		if len(c) == 0 {
			continue
		}
		h = append(h, recHead{chunk: i, idx: 0, key: c[0].SortKey()})
	}
	heap.Init(&h)
	total := 0
	for _, c := range chunks {
		total += len(c)
	}
	out := make([]IndexRecord, 0, total)
	for h.Len() > 0 {
		head := heap.Pop(&h).(recHead)
		out = append(out, chunks[head.chunk][head.idx])
		next := head.idx + 1
		if next < len(chunks[head.chunk]) {
			heap.Push(&h, recHead{
				chunk: head.chunk,
				idx:   next,
				key:   chunks[head.chunk][next].SortKey(),
			})
		}
	}
	return out
}

func filterNonEmpty(chunks [][]IndexRecord) [][]IndexRecord {
	out := make([][]IndexRecord, 0, len(chunks))
	for _, c := range chunks {
		if len(c) > 0 {
			out = append(out, c)
		}
	}
	return out
}

type recHead struct {
	chunk int
	idx   int
	key   string
}

type recHeap []recHead

func (h recHeap) Len() int           { return len(h) }
func (h recHeap) Less(i, j int) bool { return h[i].key < h[j].key }
func (h recHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *recHeap) Push(x any)        { *h = append(*h, x.(recHead)) }
func (h *recHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

func sanitizeName(s string) string {
	s = strings.Map(func(r rune) rune {
		switch r {
		case ':', '/', '\\', '*', '?', '"', '<', '>', '|':
			return '_'
		default:
			return r
		}
	}, s)
	if s == "" {
		return "hive"
	}
	return s
}

// discoverUserHives finds ProfileList SIDs already walked from SOFTWARE and maps to NTUSER.DAT.
func discoverUserHives(records *[]IndexRecord) []HiveSpec {
	const prefix = `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`
	type profile struct {
		sid  string
		path string
	}
	bySID := map[string]*profile{}
	for _, rec := range *records {
		if !strings.HasPrefix(strings.ToUpper(rec.K), strings.ToUpper(prefix)) {
			continue
		}
		rest := rec.K[len(prefix):]
		sid := strings.SplitN(rest, `\`, 2)[0]
		if !strings.HasPrefix(strings.ToUpper(sid), "S-1-5-21-") {
			continue
		}
		p := bySID[sid]
		if p == nil {
			p = &profile{sid: sid}
			bySID[sid] = p
		}
		if strings.EqualFold(rec.N, "ProfileImagePath") {
			if s, ok := rec.V.(string); ok {
				p.path = trimRegString(s)
			}
		}
	}
	var specs []HiveSpec
	for _, p := range bySID {
		if p.path == "" {
			continue
		}
		guest := strings.ReplaceAll(p.path, `%SystemDrive%`, `C:`)
		guest = strings.ReplaceAll(guest, `%systemdrive%`, `C:`)
		guest = strings.TrimRight(guest, `\`) + `\NTUSER.DAT`
		specs = append(specs, HiveSpec{
			GuestPath: guest,
			Prefix:    `HKU:\` + p.sid,
		})
	}
	return specs
}

func aliasCurrentControlSet(records *[]IndexRecord) {
	var current uint32
	found := false
	for _, rec := range *records {
		if strings.EqualFold(rec.K, `HKLM:\SYSTEM\Select`) && strings.EqualFold(rec.N, "Current") {
			if s, ok := rec.V.(string); ok {
				var v uint64
				fmt.Sscanf(s, "0x%x", &v)
				current = uint32(v)
				found = true
			}
			break
		}
	}
	if !found || current == 0 {
		current = 1
	}
	csName := fmt.Sprintf("ControlSet%03d", current)
	srcPrefix := `HKLM:\SYSTEM\` + csName
	dstPrefix := `HKLM:\SYSTEM\CurrentControlSet`
	var extras []IndexRecord
	for _, rec := range *records {
		if !strings.HasPrefix(strings.ToUpper(rec.K), strings.ToUpper(srcPrefix)) {
			continue
		}
		suffix := rec.K[len(srcPrefix):]
		clone := rec
		clone.K = dstPrefix + suffix
		extras = append(extras, clone)
	}
	*records = append(*records, extras...)
}
