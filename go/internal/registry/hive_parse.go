package registry

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"www.velocidex.com/golang/regparser"
)

const parallelHiveBytes = 8 << 20 // walk large hives by top-level key in parallel

// WalkHiveFile parses a REGF hive and appends IndexRecords under prefix.
func WalkHiveFile(hivePath, prefix string, out *[]IndexRecord) (int, error) {
	data, err := os.ReadFile(hivePath)
	if err != nil {
		return 0, err
	}
	recs, err := walkHiveBytes(data, prefix, int64(len(data)) >= parallelHiveBytes)
	if err != nil {
		return 0, err
	}
	*out = append(*out, recs...)
	return len(recs), nil
}

func walkHiveBytes(data []byte, prefix string, parallel bool) ([]IndexRecord, error) {
	r := bytes.NewReader(data)
	reg, err := regparser.NewRegistry(r)
	if err != nil {
		return nil, err
	}
	root := reg.OpenKey("")
	if root == nil {
		return nil, fmt.Errorf("hive root missing")
	}
	rootPath := normalizeRegKey(prefix, "")

	var rootRecs []IndexRecord
	emitValues(root, rootPath, &rootRecs)

	subs := root.Subkeys()
	names := make([]string, 0, len(subs))
	for _, sub := range subs {
		if sub == nil {
			continue
		}
		n := sub.Name()
		if n != "" {
			names = append(names, n)
		}
	}

	if !parallel || len(names) < 4 {
		out := make([]IndexRecord, 0, estimateRecords(len(data)))
		out = append(out, rootRecs...)
		for _, name := range names {
			child := findSubkey(root, name)
			walkKeyNode(child, rootPath+`\`+name, &out)
		}
		sortRecords(out)
		return out, nil
	}

	workers := runtime.GOMAXPROCS(0)
	if workers > len(names) {
		workers = len(names)
	}
	if workers < 2 {
		workers = 2
	}
	chunks := make([][]IndexRecord, len(names))
	ch := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr := bytes.NewReader(data)
			preg, err := regparser.NewRegistry(rr)
			if err != nil {
				return
			}
			for i := range ch {
				node := preg.OpenKey(names[i])
				var recs []IndexRecord
				walkKeyNode(node, rootPath+`\`+names[i], &recs)
				sortRecords(recs)
				chunks[i] = recs
			}
		}()
	}
	for i := range names {
		ch <- i
	}
	close(ch)
	wg.Wait()

	sortRecords(rootRecs)
	all := make([][]IndexRecord, 0, 1+len(chunks))
	if len(rootRecs) > 0 {
		all = append(all, rootRecs)
	}
	all = append(all, chunks...)
	return mergeSortedRecords(all), nil
}

func findSubkey(node *regparser.CM_KEY_NODE, name string) *regparser.CM_KEY_NODE {
	if node == nil {
		return nil
	}
	want := strings.ToLower(name)
	for _, sub := range node.Subkeys() {
		if sub != nil && strings.ToLower(sub.Name()) == want {
			return sub
		}
	}
	return nil
}

func estimateRecords(hiveBytes int) int {
	n := hiveBytes / 180
	if n < 256 {
		return 256
	}
	if n > 600000 {
		return 600000
	}
	return n
}

func walkKeyNode(node *regparser.CM_KEY_NODE, keyPath string, out *[]IndexRecord) {
	if node == nil {
		return
	}
	if shouldSkipRegistryKey(keyPath) {
		return
	}
	emitValues(node, keyPath, out)
	for _, sub := range node.Subkeys() {
		if sub == nil {
			continue
		}
		childName := sub.Name()
		if childName == "" {
			continue
		}
		walkKeyNode(sub, keyPath+`\`+childName, out)
	}
}

func emitValues(node *regparser.CM_KEY_NODE, keyPath string, out *[]IndexRecord) {
	for _, val := range node.Values() {
		if val == nil {
			continue
		}
		data := rawValueBytes(val)
		typ := val.Type()
		rec := IndexRecord{
			K:    keyPath,
			N:    val.ValueName(),
			T:    regTypeName(typ),
			H:    contentHashRaw(typ, data),
			Size: len(data),
		}
		*out = append(*out, rec)
	}
}

func rawValueBytes(val *regparser.CM_KEY_VALUE) []byte {
	dataSize := val.DataLength()
	if dataSize&0x80000000 > 0 {
		dataSize ^= 0x80000000
		return regparser.ParseSafeArray_byte(
			val.Reader,
			val.Offset+val.Profile.Off_CM_KEY_VALUE_Data,
			4,
		)
	}
	cell := val.Profile.HCELL(val.Reader, 0x1000+int64(val.Data()))
	if cell.Signature() == 0x6264 /* db */ {
		big := val.Profile.CM_BIG_DATA(val.Reader, cell.Payload())
		listCell := val.Profile.HCELL(val.Reader, 0x1000+int64(big.List()))
		segmentList := regparser.ParseSafeArray_uint32(val.Reader, listCell.Payload(), int(big.Count()))
		var out []byte
		remain := dataSize
		for _, offset := range segmentList {
			seg := val.Profile.HCELL(val.Reader, 0x1000+int64(offset))
			if !seg.Allocated() {
				continue
			}
			n := seg.DataSize()
			if n > remain {
				n = remain
			}
			out = append(out, regparser.ParseSafeArray_byte(val.Reader, seg.Payload(), int(n))...)
			remain -= n
			if remain == 0 {
				break
			}
		}
		return out
	}
	return regparser.ParseSafeArray_byte(val.Reader, cell.Payload(), int(dataSize))
}

func contentHashRaw(typ uint32, data []byte) string {
	h := fnv.New64a()
	var t [4]byte
	binary.LittleEndian.PutUint32(t[:], typ)
	_, _ = h.Write(t[:])
	_, _ = h.Write(data)
	return strconv.FormatUint(h.Sum64(), 16)
}

func regTypeName(t uint32) string {
	return regparser.RegTypeToString(t)
}

func trimRegString(s string) string {
	s = strings.TrimRight(s, "\x00")
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, 0); i >= 0 {
		s = s[:i]
	}
	return s
}

func valuePayload(vd *regparser.ValueData, typ string) (any, []byte) {
	if vd == nil {
		return nil, nil
	}
	data := vd.Data
	switch typ {
	case "REG_SZ", "REG_EXPAND_SZ":
		s := vd.String
		if s == "" && len(data) > 0 {
			s = string(data)
		}
		s = trimRegString(s)
		return s, []byte(s)
	case "REG_MULTI_SZ":
		if len(vd.MultiSz) > 0 {
			cleaned := make([]string, 0, len(vd.MultiSz))
			for _, part := range vd.MultiSz {
				part = trimRegString(part)
				if part != "" {
					cleaned = append(cleaned, part)
				}
			}
			joined := strings.Join(cleaned, "\n")
			return cleaned, []byte(joined)
		}
		return nil, data
	case "REG_DWORD", "REG_QWORD":
		return fmt.Sprintf("0x%x", vd.Uint64), data
	default:
		if len(data) == 0 {
			return nil, nil
		}
		return fmt.Sprintf("%x", data), data
	}
}

func shouldSkipRegistryKey(key string) bool {
	u := strings.ToUpper(key)
	patterns := []string{
		`\IRISSERVICE\CACHE\`,
		`\TASKCACHE\TASKS\{`,
		`\EXPLORER\SESSIONINFO\`,
		`\CONTENTDELIVERYMANAGER\`,
		`\INSTALLSERVICE\STATE`,
		`\VOLATILE ENVIRONMENT\`,
		`\APPCOMPATFLAGS\COMPATIBILITY ASSISTANT\`,
		`\WINDOWS\WINDOWS ERROR REPORTING\`,
	}
	for _, p := range patterns {
		if strings.Contains(u, p) {
			return true
		}
	}
	return false
}
