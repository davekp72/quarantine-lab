//go:build windows

package collectors

import (
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	fileIDPathCache               sync.Map
	pathResolveBudget             int32 = -1
	pathVolHandle                 windows.Handle
	pathVolOnce                   sync.Once
	pathVolErr                    error
	modKernel32                   = windows.NewLazySystemDLL("kernel32.dll")
	procOpenFileById              = modKernel32.NewProc("OpenFileById")
	procGetFinalPathNameByHandleW = modKernel32.NewProc("GetFinalPathNameByHandleW")
)

const (
	fileIdType         = 0
	extendedFileIdType = 2
	volumeNameDOS      = 0
)

type fileIDDescriptor struct {
	Size uint32
	Type uint32
	ID   [16]byte
}

// BeginPathResolveBudget limits path-resolution syscalls for one capture.
// Pass n <= 0 for unlimited (tests only).
func BeginPathResolveBudget(n int) func() {
	var v int32 = -1
	if n > 0 {
		v = int32(n)
	}
	old := atomic.SwapInt32(&pathResolveBudget, v)
	fileIDPathCache.Range(func(k, _ any) bool {
		fileIDPathCache.Delete(k)
		return true
	})
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

func volumeHint(volume string) windows.Handle {
	pathVolOnce.Do(func() {
		pathVolHandle, pathVolErr = openVolume(volume)
	})
	if pathVolErr != nil {
		return 0
	}
	return pathVolHandle
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
	path := openFileByID(volume, fileRefHex)
	if path == "" {
		path = fsutilQueryFileName(volume, fileRefHex)
	}
	fileIDPathCache.Store(fileRefHex, path)
	return path
}

func openFileByID(volume, fileRefHex string) string {
	id, typ, ok := parseFileRef(fileRefHex)
	if !ok {
		return ""
	}
	hVol := volumeHint(volume)
	if hVol == 0 {
		return ""
	}
	desc := fileIDDescriptor{Size: uint32(unsafe.Sizeof(fileIDDescriptor{})), Type: typ, ID: id}
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	flags := uint32(fileFlagBackupSemantics)
	r0, _, _ := procOpenFileById.Call(
		uintptr(hVol),
		uintptr(unsafe.Pointer(&desc)),
		0,
		uintptr(share),
		0,
		uintptr(flags),
	)
	h := windows.Handle(r0)
	if h == 0 || h == windows.InvalidHandle {
		return ""
	}
	defer windows.CloseHandle(h)
	return finalPathFromHandle(h)
}

func finalPathFromHandle(h windows.Handle) string {
	n, _, _ := procGetFinalPathNameByHandleW.Call(uintptr(h), 0, 0, volumeNameDOS)
	if n == 0 {
		return ""
	}
	buf := make([]uint16, n+2)
	n, _, _ = procGetFinalPathNameByHandleW.Call(uintptr(h), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), volumeNameDOS)
	if n == 0 {
		return ""
	}
	s := windows.UTF16ToString(buf)
	s = strings.TrimPrefix(s, `\\?\`)
	s = strings.TrimPrefix(s, `\??\`)
	return normalizePath(s)
}

func parseFileRef(hexRef string) (id [16]byte, typ uint32, ok bool) {
	s := strings.TrimSpace(hexRef)
	s = strings.TrimPrefix(strings.ToLower(s), "0x")
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) == 0 {
		return id, 0, false
	}
	if len(raw) <= 8 {
		typ = fileIdType
		var n uint64
		for _, b := range raw {
			n = (n << 8) | uint64(b)
		}
		for i := 0; i < 8; i++ {
			id[i] = byte(n >> (8 * i))
		}
		return id, typ, true
	}
	typ = extendedFileIdType
	copy(id[:], raw)
	return id, typ, true
}

func fsutilQueryFileName(volume, fileRefHex string) string {
	vol := normalizeVolumeLetter(volume)
	if !strings.HasSuffix(vol, `\`) {
		vol += `\`
	}
	out, err := exec.Command("fsutil.exe", "file", "queryFileNameById", vol, fileRefHex).CombinedOutput()
	if err != nil {
		return ""
	}
	return parseQueryFileNameByIdOutput(string(out))
}

func parseQueryFileNameByIdOutput(text string) string {
	text = strings.TrimSpace(text)
	// Typical: "A file with id 0x... exists at path C:\Windows\..."
	lower := strings.ToLower(text)
	if i := strings.Index(lower, `c:\`); i >= 0 {
		rest := text[i:]
		if f := strings.Fields(rest); len(f) > 0 {
			return normalizePath(f[0])
		}
	}
	if idx := strings.Index(text, `:\`); idx > 0 {
		start := idx - 1
		if start >= 0 && ((text[start] >= 'A' && text[start] <= 'Z') || (text[start] >= 'a' && text[start] <= 'z')) {
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

func parentRefFromRecord(buf []byte, offset int, major uint16) string {
	switch major {
	case 2:
		lo := leUint64(buf[offset+16 : offset+24])
		return fmt.Sprintf("0x%016x", lo)
	case 3, 4:
		if offset+40 > len(buf) {
			return ""
		}
		return "0x" + strings.ToUpper(hex.EncodeToString(buf[offset+24:offset+40]))
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

func usnEventPath(volume, fileName, fileRef, parentRef string) string {
	if fileRef != "" {
		if p := resolvePathByFileRef(volume, fileRef); p != "" {
			return p
		}
	}
	if parentRef != "" && fileName != "" && !strings.Contains(fileName, `\`) {
		if dir := resolvePathByFileRef(volume, parentRef); dir != "" {
			return normalizePath(dir + `\` + fileName)
		}
	}
	return resolveUsnPathFallback(fileName)
}
