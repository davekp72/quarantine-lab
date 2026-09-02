//go:build windows

package collectors

import (
	"encoding/hex"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

var (
	fileIDPathCache   sync.Map
	queryNameRe       = regexp.MustCompile(`(?i)(?:\\?\?\\)?([A-Za-z]:\\[^\r\n"]+)`)
	pathResolveBudget int32 = -1
)

// BeginPathResolveBudget limits fsutil queryFileNameById calls for one capture.
// Pass n <= 0 for unlimited (tests only).
func BeginPathResolveBudget(n int) func() {
	var v int32 = -1
	if n > 0 {
		v = int32(n)
	}
	old := atomic.SwapInt32(&pathResolveBudget, v)
	return func() { atomic.StoreInt32(&pathResolveBudget, old) }
}

func takePathResolveSlot() bool {
	b := atomic.LoadInt32(&pathResolveBudget)
	if b < 0 {
		return true
	}
	for {
		if b == 0 {
			return false
		}
		if atomic.CompareAndSwapInt32(&pathResolveBudget, b, b-1) {
			return true
		}
		b = atomic.LoadInt32(&pathResolveBudget)
	}
}

func resolvePathByFileRef(volume, fileRefHex string) string {
	fileRefHex = strings.TrimSpace(fileRefHex)
	if fileRefHex == "" {
		return ""
	}
	if v, ok := fileIDPathCache.Load(fileRefHex); ok {
		return v.(string)
	}
	if !takePathResolveSlot() {
		return ""
	}
	vol := normalizeVolumeLetter(volume)
	if !strings.HasSuffix(vol, `\`) {
		vol += `\`
	}
	out, err := exec.Command("fsutil.exe", "file", "queryFileNameById", vol, fileRefHex).CombinedOutput()
	if err != nil {
		fileIDPathCache.Store(fileRefHex, "")
		return ""
	}
	path := parseQueryFileNameByIdOutput(string(out))
	fileIDPathCache.Store(fileRefHex, path)
	return path
}

func parseQueryFileNameByIdOutput(text string) string {
	text = strings.TrimSpace(text)
	if m := queryNameRe.FindStringSubmatch(text); len(m) > 1 {
		return normalizePath(m[1])
	}
	if idx := strings.Index(text, ":\\"); idx > 0 {
		start := idx - 1
		if start >= 0 && (text[start] >= 'A' && text[start] <= 'Z' || text[start] >= 'a' && text[start] <= 'z') {
			return normalizePath(strings.Fields(text[start:])[0])
		}
	}
	return ""
}

func fileRefFromRecord(buf []byte, offset int, major uint16) string {
	switch major {
	case 2:
		lo := leUint64(buf[offset+8 : offset+16])
		return fmt.Sprintf("0x%016x", lo)
	case 3, 4:
		if offset+24 > len(buf) {
			return ""
		}
		return "0x" + strings.ToUpper(hex.EncodeToString(buf[offset+8:offset+24]))
	default:
		return ""
	}
}

func leUint64(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	var n uint64
	for i := 0; i < 8; i++ {
		n |= uint64(b[i]) << (8 * i)
	}
	return n
}

func fileRefFromFsutilCols(cols []string) string {
	if len(cols) > 2 {
		ref := strings.Trim(cols[2], `"`)
		if looksLikeFileRef(ref) {
			return ref
		}
	}
	return ""
}

func usnEventPath(volume, fileName, fileRef string) string {
	if fileRef != "" {
		if p := resolvePathByFileRef(volume, fileRef); p != "" {
			return p
		}
	}
	return resolveUsnPath(fileName)
}

func isLeafOnlyPath(p string) bool {
	p = normalizePath(p)
	if len(p) < 4 || p[1] != ':' {
		return false
	}
	rest := strings.TrimPrefix(p, p[:3])
	rest = strings.TrimPrefix(rest, `\`)
	return rest != "" && !strings.Contains(rest, `\`)
}
