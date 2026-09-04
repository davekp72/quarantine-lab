package registry

import (
	"bytes"
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

	"www.velocidex.com/golang/regparser"
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
	meta      HiveMeta
	records   []IndexRecord // sorted by SortKey
	localPath string
}

// BuildIndexFromLocalHives walks already-copied hive files in parallel and writes sorted index + meta.
func BuildIndexFromLocalHives(snapshotName, indexPath, metaPath string, files []LocalHiveFile) (*IndexMeta, error) {
	meta := &IndexMeta{
		Engine:   "hive",
		Format:   IndexFormatSlim,
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
		Format:   IndexFormatSlim,
		Snapshot: snapshotName,
		BuiltAt:  time.Now().UTC().Format(time.RFC3339),
		Digests:  map[string]string{},
	}

	sysResults := extractAndWalkParallel(dx, snapshotName, workDir, systemHives)
	var sysChunks [][]IndexRecord
	var softwarePath string
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
		if r.meta.Prefix == `HKLM:\SOFTWARE` && r.localPath != "" && r.meta.Error == "" {
			softwarePath = r.localPath
		}
	}
	userHives := discoverUserHivesFromHive(softwarePath)
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
	data, err := os.ReadFile(f.LocalPath)
	if err != nil {
		hm.Error = err.Error()
		return hiveWalkResult{meta: hm, localPath: f.LocalPath}
	}
	hm.Size = int64(len(data))
	sum := sha256.Sum256(data)
	hm.SHA256 = hex.EncodeToString(sum[:])
	recs, err := walkHiveBytes(data, f.Prefix, int64(len(data)) >= parallelHiveBytes)
	if err != nil {
		hm.Error = err.Error()
		return hiveWalkResult{meta: hm, localPath: f.LocalPath}
	}
	hm.Entries = len(recs)
	return hiveWalkResult{meta: hm, records: recs, localPath: f.LocalPath}
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
	_, err := dx.ExtractFile(snapshotName, spec.GuestPath, local)
	if err != nil {
		hm.Error = err.Error()
		return hiveWalkResult{meta: hm, localPath: local}
	}
	data, err := os.ReadFile(local)
	if err != nil {
		hm.Error = err.Error()
		return hiveWalkResult{meta: hm, localPath: local}
	}
	hm.Size = int64(len(data))
	sum := sha256.Sum256(data)
	hm.SHA256 = hex.EncodeToString(sum[:])
	recs, err := walkHiveBytes(data, spec.Prefix, int64(len(data)) >= parallelHiveBytes)
	if err != nil {
		hm.Error = err.Error()
		return hiveWalkResult{meta: hm, localPath: local}
	}
	hm.Entries = len(recs)
	return hiveWalkResult{meta: hm, records: recs, localPath: local}
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

func discoverUserHivesFromHive(softwarePath string) []HiveSpec {
	if softwarePath == "" {
		return nil
	}
	data, err := os.ReadFile(softwarePath)
	if err != nil {
		return nil
	}
	reg, err := regparser.NewRegistry(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	node := reg.OpenKey(`Microsoft\Windows NT\CurrentVersion\ProfileList`)
	if node == nil {
		return nil
	}
	var specs []HiveSpec
	for _, sub := range node.Subkeys() {
		if sub == nil {
			continue
		}
		sid := sub.Name()
		if !strings.HasPrefix(strings.ToUpper(sid), "S-1-5-21-") {
			continue
		}
		var img string
		for _, val := range sub.Values() {
			if val == nil || !strings.EqualFold(val.ValueName(), "ProfileImagePath") {
				continue
			}
			raw, _ := valuePayload(val.ValueData(), val.TypeString())
			if s, ok := raw.(string); ok {
				img = trimRegString(s)
			}
		}
		if img == "" {
			continue
		}
		guest := strings.ReplaceAll(img, `%SystemDrive%`, `C:`)
		guest = strings.ReplaceAll(guest, `%systemdrive%`, `C:`)
		guest = strings.TrimRight(guest, `\`) + `\NTUSER.DAT`
		specs = append(specs, HiveSpec{GuestPath: guest, Prefix: `HKU:\` + sid})
	}
	return specs
}
