//go:build windows

package collectors

import (
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
	"unsafe"

	"github.com/quarantine-lab/quarantine/internal/agent/privileges"
	"golang.org/x/sys/windows"
)

const (
	fsctlQueryUsnJournal    = 0x000900f4
	fsctlReadUsnJournal     = 0x000900bb
	fsctlEnumUsnData        = 0x000900b3
	fileFlagBackupSemantics = 0x02000000
	fileTraverse            = 0x0020
)

type usnJournalData struct {
	UsnJournalID    uint64
	FirstUsn        int64
	NextUsn         int64
	LowestValidUsn  int64
	MaxUsn          int64
	MaximumSize     uint64
	AllocationDelta uint64
}

type readUsnJournalData struct {
	StartUsn          int64
	ReasonMask        uint32
	ReturnOnlyOnClose uint32
	Timeout           uint64
	BytesToWaitFor    uint64
	UsnJournalID      uint64
}

var usnReasonLabels = map[uint32]string{
	0x00000001: "data_extend",
	0x00000002: "data_truncation",
	0x00000004: "named_data_overwrite",
	0x00000010: "data_overwrite",
	0x00000100: "file_create",
	0x00000200: "file_delete",
	0x00000400: "ea_change",
	0x00000800: "security_change",
	0x00001000: "rename_old_name",
	0x00002000: "rename_new_name",
	0x00004000: "indexable_change",
	0x00008000: "basic_info_change",
	0x00010000: "hard_link_change",
	0x00020000: "compression_change",
	0x00080000: "reparse_point_change",
	0x00100000: "stream_change",
	0x00200000: "close",
}

// File content / identity changes. Excludes close-only and low-signal chatter.
const usnChangeReasonMask uint32 = 0x00000001 | 0x00000002 | 0x00000004 | 0x00000010 |
	0x00000020 | 0x00000040 | 0x00000100 | 0x00000200 | 0x00001000 | 0x00002000 |
	0x00008000 | 0x00010000 | 0x00080000 | 0x00100000

// DefaultVolume returns the NTFS volume used for USN journaling.
func DefaultVolume() string {
	if sd := strings.TrimSpace(os.Getenv("SystemDrive")); sd != "" {
		return normalizeVolumeLetter(sd)
	}
	return `C:`
}

func normalizeVolumeLetter(volume string) string {
	vol := strings.TrimSpace(volume)
	vol = strings.TrimRight(vol, `\`)
	if vol == "" {
		return `C:`
	}
	if !strings.HasSuffix(vol, ":") {
		if len(vol) == 1 {
			vol += ":"
		}
	}
	return vol
}

func volumeDevicePath(volume string) string {
	return `\\.\` + normalizeVolumeLetter(volume)
}

// USNAvailable reports whether the USN journal can be queried on the system volume.
func USNAvailable() bool {
	_ = privileges.EnableManifestRead()
	_, err := queryUsnJournal(DefaultVolume())
	return err == nil
}

// Baseline captures current USN journal position.
func Baseline(volume string) (json.RawMessage, error) {
	_ = privileges.EnableManifestRead()
	if volume == "" {
		volume = DefaultVolume()
	}
	volume = normalizeVolumeLetter(volume)
	info, err := queryUsnJournal(volume)
	if err != nil {
		return nil, err
	}
	obj := map[string]any{
		"version":    1,
		"volume":     volume,
		"recordedAt": time.Now().UTC().Format(time.RFC3339),
		"journalId":  fmt.Sprintf("0x%016x", info.UsnJournalID),
		"startUsn":   fmt.Sprintf("0x%016x", uint64(info.NextUsn)),
		"firstUsn":   fmt.Sprintf("0x%016x", uint64(info.FirstUsn)),
		"computer":   os.Getenv("COMPUTERNAME"),
	}
	raw, err := json.Marshal(obj)
	return raw, err
}

// USNDelta returns journal records since baseline JSON.
func USNDelta(baselineRaw json.RawMessage, maxEvents int) (json.RawMessage, int, error) {
	_ = privileges.EnableManifestRead()
	if maxEvents <= 0 {
		maxEvents = 50000
	}
	var baseline map[string]any
	if err := json.Unmarshal(baselineRaw, &baseline); err != nil {
		return nil, 0, fmt.Errorf("parse baseline: %w", err)
	}
	volume, _ := baseline["volume"].(string)
	if volume == "" {
		volume = DefaultVolume()
	}
	volume = normalizeVolumeLetter(volume)
	startUsnStr, _ := baseline["startUsn"].(string)
	startUsn, err := parseUsnValue(startUsnStr)
	if err != nil {
		return nil, 0, fmt.Errorf("baseline startUsn: %w", err)
	}
	baselineAt, _ := baseline["recordedAt"].(string)

	info, err := queryUsnJournal(volume)
	if err != nil {
		return nil, 0, err
	}
	endUsn := uint64(info.NextUsn)
	readStart := startUsn
	readStartStr := startUsnStr
	warnings := []string{}
	timeFloor := time.Time{}
	if endUsn < startUsn {
		warnings = append(warnings,
			"USN baseline is ahead of the volume (snapshot was frozen before baseline capture). Retake the session baseline snapshot. Reading journal with a time floor.")
		readStart = uint64(info.FirstUsn)
		if readStart == 0 {
			readStart = uint64(info.LowestValidUsn)
		}
		readStartStr = fmt.Sprintf("0x%016x", readStart)
		if t, err := time.Parse(time.RFC3339, baselineAt); err == nil {
			timeFloor = t.Add(-10 * time.Minute)
		}
	} else if info.FirstUsn > 0 && startUsn < uint64(info.FirstUsn) {
		warnings = append(warnings,
			"USN baseline start was deleted from the journal (wrapped). Reading from FirstUsn; early changes may be missing. Re-mark with reset -Clean.")
		readStart = uint64(info.FirstUsn)
		readStartStr = fmt.Sprintf("0x%016x", readStart)
	} else if endUsn == startUsn {
		out, _ := json.Marshal(map[string]any{
			"available":  true,
			"eventCount": 0,
			"volume":     volume,
			"startUsn":   startUsnStr,
			"endUsn":     fmt.Sprintf("0x%016x", endUsn),
			"recordedAt": time.Now().UTC().Format(time.RFC3339),
			"baselineAt": baselineAt,
			"message":    "No USN activity since baseline.",
			"events":     []any{},
		})
		return out, 0, nil
	}

	rawEvents, err := readUsnRecords(volume, info.UsnJournalID, readStartStr, int64(readStart), int64(endUsn), maxEvents)
	if err != nil {
		return nil, 0, err
	}
	filterStart := startUsn
	if endUsn < startUsn || (info.FirstUsn > 0 && startUsn < uint64(info.FirstUsn)) {
		filterStart = 0
	}
	events, noise, skipped := FinalizeUSNEvents(volume, rawEvents, filterStart, timeFloor)
	outObj := map[string]any{
		"available":  true,
		"eventCount": len(events),
		"rawCount":   len(rawEvents),
		"volume":     volume,
		"startUsn":   startUsnStr,
		"endUsn":     fmt.Sprintf("0x%016x", endUsn),
		"recordedAt": time.Now().UTC().Format(time.RFC3339),
		"baselineAt": baselineAt,
		"events":     events,
		"noise":      noise,
	}
	if skipped > 0 {
		outObj["skippedBeforeBaseline"] = skipped
	}
	if len(warnings) > 0 {
		outObj["warnings"] = warnings
	}
	if len(rawEvents) >= maxEvents {
		outObj["truncated"] = true
	}
	out, _ := json.Marshal(outObj)
	return out, len(events), nil
}

func BaselineMarker(message string, baselineRaw json.RawMessage) json.RawMessage {
	recordedAt := time.Now().UTC().Format(time.RFC3339)
	startUsn := ""
	if baselineRaw != nil {
		var b map[string]any
		if json.Unmarshal(baselineRaw, &b) == nil {
			if v, ok := b["recordedAt"].(string); ok {
				recordedAt = v
			}
			startUsn, _ = b["startUsn"].(string)
		}
	}
	m := map[string]any{
		"available":  true,
		"eventCount": 0,
		"message":    message,
		"baselineAt": recordedAt,
		"recordedAt": recordedAt,
		"events":     []any{},
	}
	if startUsn != "" {
		m["startUsn"] = startUsn
	}
	raw, _ := json.Marshal(m)
	return raw
}

func openVolume(volume string) (windows.Handle, error) {
	_ = privileges.EnableManifestRead()
	path := volumeDevicePath(volume)
	specs := []struct {
		access uint32
		flags  uint32
	}{
		{windows.GENERIC_READ | windows.GENERIC_WRITE, fileFlagBackupSemantics},
		{windows.GENERIC_READ | windows.GENERIC_WRITE, 0},
		{windows.GENERIC_READ, fileFlagBackupSemantics},
		{windows.SYNCHRONIZE | fileTraverse, windows.FILE_ATTRIBUTE_NORMAL},
	}
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
		for _, spec := range specs {
			h, err := createVolumeHandle(path, spec.access, spec.flags)
			if err == nil {
				return h, nil
			}
			lastErr = err
			if !isAccessDenied(err) {
				return 0, fmt.Errorf("open volume %q: %w", path, err)
			}
		}
	}
	return 0, fmt.Errorf("open volume %q: %w", path, lastErr)
}

func createVolumeHandle(path string, access, flags uint32) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(p, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, flags, 0)
}

func isAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	if errno, ok := err.(windows.Errno); ok && errno == windows.ERROR_ACCESS_DENIED {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "access is denied")
}

func queryUsnJournal(volume string) (*usnJournalData, error) {
	_ = privileges.EnableManifestRead()
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
		info, err := queryUsnJournalHandle(volume)
		if err == nil {
			return info, nil
		}
		lastErr = err
		if !isAccessDenied(err) {
			return nil, err
		}
	}
	if info, err := queryUsnJournalFsutil(volume); err == nil {
		return info, nil
	}
	return nil, lastErr
}

func queryUsnJournalHandle(volume string) (*usnJournalData, error) {
	h, err := openVolume(volume)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)

	buf := make([]byte, 1024)
	var returned uint32
	err = windows.DeviceIoControl(h, fsctlQueryUsnJournal, nil, 0, &buf[0], uint32(len(buf)), &returned, nil)
	if err != nil {
		return nil, fmt.Errorf("query USN journal: %w", err)
	}
	if returned < 64 {
		return nil, fmt.Errorf("short USN journal data")
	}
	return decodeUsnJournalData(buf), nil
}

func decodeUsnJournalData(buf []byte) *usnJournalData {
	return &usnJournalData{
		UsnJournalID:    binary.LittleEndian.Uint64(buf[0:8]),
		FirstUsn:        int64(binary.LittleEndian.Uint64(buf[8:16])),
		NextUsn:         int64(binary.LittleEndian.Uint64(buf[16:24])),
		LowestValidUsn:  int64(binary.LittleEndian.Uint64(buf[24:32])),
		MaxUsn:          int64(binary.LittleEndian.Uint64(buf[32:40])),
		MaximumSize:     binary.LittleEndian.Uint64(buf[40:48]),
		AllocationDelta: binary.LittleEndian.Uint64(buf[48:56]),
	}
}

var fsutilFieldRe = regexp.MustCompile(`(?m)^\s*([^:]+)\s*:\s*(.+)$`)

func queryUsnJournalFsutil(volume string) (*usnJournalData, error) {
	vol := normalizeVolumeLetter(volume)
	out, err := exec.Command("fsutil.exe", "usn", "queryjournal", vol).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("fsutil usn queryjournal: %w: %s", err, strings.TrimSpace(string(out)))
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		m := fsutilFieldRe.FindStringSubmatch(line)
		if len(m) != 3 {
			continue
		}
		key := strings.ReplaceAll(strings.TrimSpace(m[1]), " ", "")
		fields[key] = strings.TrimSpace(m[2])
	}
	id, err1 := parseUsnValue(fields["UsnJournalID"])
	first, err2 := parseUsnValue(fields["FirstUsn"])
	next, err3 := parseUsnValue(fields["NextUsn"])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, fmt.Errorf("parse fsutil journal output")
	}
	return &usnJournalData{
		UsnJournalID: id,
		FirstUsn:     int64(first),
		NextUsn:      int64(next),
	}, nil
}

func readUsnRecords(volume string, journalID uint64, startUsnHex string, lowUsn, highUsn int64, maxEvents int) ([]map[string]any, error) {
	_ = privileges.EnableManifestRead()
	tryPaths := []struct {
		name string
		fn   func() ([]map[string]any, error)
	}{
		{"read-v1", func() ([]map[string]any, error) {
			return readUsnRecordsHandle(volume, journalID, lowUsn, maxEvents, true)
		}},
		{"read-v0", func() ([]map[string]any, error) {
			return readUsnRecordsHandle(volume, journalID, lowUsn, maxEvents, false)
		}},
		{"fsutil", func() ([]map[string]any, error) {
			return readUsnRecordsFsutil(volume, startUsnHex, maxEvents)
		}},
	}
	var errs []string
	for _, path := range tryPaths {
		events, err := path.fn()
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", path.name, err))
			continue
		}
		if len(events) == 0 {
			errs = append(errs, fmt.Sprintf("%s: 0 events", path.name))
			continue
		}
		if usnEventsLookInvalid(events) {
			errs = append(errs, fmt.Sprintf("%s: invalid event shape", path.name))
			continue
		}
		return events, nil
	}
	return nil, fmt.Errorf("%s", strings.Join(errs, "; "))
}

func readUsnRecordsEnum(volume string, lowUsn, highUsn int64, maxEvents int) ([]map[string]any, error) {
	h, err := openVolumeForRead(volume)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)

	inBuf := make([]byte, 32)
	outBuf := make([]byte, 256*1024)
	var events []map[string]any
	startFileRef := uint64(0)

	for len(events) < maxEvents {
		binary.LittleEndian.PutUint64(inBuf[0:8], startFileRef)
		binary.LittleEndian.PutUint64(inBuf[8:16], uint64(lowUsn))
		binary.LittleEndian.PutUint64(inBuf[16:24], uint64(highUsn))
		binary.LittleEndian.PutUint16(inBuf[24:26], 2)
		binary.LittleEndian.PutUint16(inBuf[26:28], 4)

		var returned uint32
		err = windows.DeviceIoControl(h, fsctlEnumUsnData, &inBuf[0], uint32(len(inBuf)), &outBuf[0], uint32(len(outBuf)), &returned, nil)
		if err != nil {
			if len(events) > 0 {
				break
			}
			return nil, fmt.Errorf("enum USN journal: %w", err)
		}
		if returned <= 8 {
			break
		}
		nextRef := binary.LittleEndian.Uint64(outBuf[0:8])
		parsed := parseUsnRecordBuffer(outBuf, 8, int(returned), maxEvents-len(events))
		events = append(events, parsed...)
		if nextRef == startFileRef || len(parsed) == 0 {
			break
		}
		startFileRef = nextRef
	}
	return events, nil
}

func readUsnRecordsHandle(volume string, journalID uint64, startUsn int64, maxEvents int, useV1Input bool) ([]map[string]any, error) {
	h, err := openVolumeForRead(volume)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)

	readData := readUsnJournalData{
		StartUsn:          startUsn,
		ReasonMask:        usnChangeReasonMask,
		ReturnOnlyOnClose: 0,
		Timeout:           0,
		BytesToWaitFor:    0,
		UsnJournalID:      journalID,
	}
	inSize := 40
	if useV1Input {
		inSize = 48
	}
	inBuf := make([]byte, inSize)
	binary.LittleEndian.PutUint64(inBuf[0:8], uint64(readData.StartUsn))
	binary.LittleEndian.PutUint32(inBuf[8:12], readData.ReasonMask)
	binary.LittleEndian.PutUint32(inBuf[12:16], readData.ReturnOnlyOnClose)
	binary.LittleEndian.PutUint64(inBuf[16:24], readData.Timeout)
	binary.LittleEndian.PutUint64(inBuf[24:32], readData.BytesToWaitFor)
	binary.LittleEndian.PutUint64(inBuf[32:40], readData.UsnJournalID)
	if useV1Input {
		binary.LittleEndian.PutUint16(inBuf[40:42], 2)
		binary.LittleEndian.PutUint16(inBuf[42:44], 4)
	}

	outBuf := make([]byte, 256*1024)
	var events []map[string]any
	nextStart := startUsn

	for len(events) < maxEvents {
		binary.LittleEndian.PutUint64(inBuf[0:8], uint64(nextStart))
		var returned uint32
		err = windows.DeviceIoControl(h, fsctlReadUsnJournal, &inBuf[0], uint32(len(inBuf)), &outBuf[0], uint32(len(outBuf)), &returned, nil)
		if err != nil {
			if len(events) > 0 {
				break
			}
			return nil, fmt.Errorf("read USN journal: %w", err)
		}
		if returned <= 8 {
			break
		}
		nextStart = int64(binary.LittleEndian.Uint64(outBuf[0:8]))
		parsed := parseUsnRecordBuffer(outBuf, 8, int(returned), maxEvents-len(events))
		events = append(events, parsed...)
		if nextStart <= startUsn || len(parsed) == 0 {
			break
		}
		startUsn = nextStart
	}
	return events, nil
}

func parseUsnRecordBuffer(buf []byte, offset, end, limit int) []map[string]any {
	var events []map[string]any
	for offset+60 <= end && len(events) < limit {
		recLen := int(binary.LittleEndian.Uint32(buf[offset : offset+4]))
		if recLen < 60 || offset+recLen > end {
			break
		}
		ev, ok := decodeUsnRecord(buf, offset, recLen)
		if ok {
			events = append(events, ev)
		}
		offset += recLen
		// USN_RECORD_V3+ records are 64-bit aligned within the IOCTL buffer.
		if rem := offset % 8; rem != 0 {
			offset += 8 - rem
		}
	}
	return events
}

func openVolumeForRead(volume string) (windows.Handle, error) {
	_ = privileges.EnableManifestRead()
	path := volumeDevicePath(volume)
	specs := []struct {
		access uint32
		flags  uint32
	}{
		{windows.GENERIC_READ | windows.GENERIC_WRITE, fileFlagBackupSemantics},
		{windows.GENERIC_READ | windows.GENERIC_WRITE, 0},
		{windows.GENERIC_READ, fileFlagBackupSemantics},
	}
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
		for _, spec := range specs {
			h, err := createVolumeHandle(path, spec.access, spec.flags)
			if err == nil {
				return h, nil
			}
			lastErr = err
		}
	}
	return 0, fmt.Errorf("open volume %q: %w", path, lastErr)
}

func decodeUsnRecord(buf []byte, offset, recLen int) (map[string]any, bool) {
	major := binary.LittleEndian.Uint16(buf[offset+4 : offset+6])
	usnOff, reasonOff, nameLenOff, nameOffOff, ok := usnRecordFieldOffsets(major)
	if !ok || offset+nameOffOff+2 > offset+recLen {
		return nil, false
	}
	usn := int64(binary.LittleEndian.Uint64(buf[offset+usnOff : offset+usnOff+8]))
	reason := binary.LittleEndian.Uint32(buf[offset+reasonOff : offset+reasonOff+4])
	nameLen := int(binary.LittleEndian.Uint16(buf[offset+nameLenOff : offset+nameLenOff+2]))
	nameOff := int(binary.LittleEndian.Uint16(buf[offset+nameOffOff : offset+nameOffOff+2]))
	nameStart := offset + nameOff
	nameEnd := nameStart + nameLen
	if nameLen == 0 || nameEnd > offset+recLen {
		return nil, false
	}
	name := stringutf16(buf[nameStart:nameEnd])
	if !looksLikeUsnFileName(name) {
		return nil, false
	}
	fileRef := fileRefFromRecord(buf, offset, major)
	parentRef := parentRefFromRecord(buf, offset, major)
	ev := map[string]any{
		"usn":        fmt.Sprintf("0x%016x", uint64(usn)),
		"fileName":   name,
		"fileRef":    fileRef,
		"parentRef":  parentRef,
		"reason":     reasonLabels(reason),
		"reasonCode": fmt.Sprintf("0x%08x", reason),
	}
	if ts := filetimeRFC3339(buf[offset+usnOff+8 : offset+usnOff+16]); ts != "" {
		ev["timestamp"] = ts
	}
	return ev, true
}

func filetimeRFC3339(b []byte) string {
	if len(b) < 8 {
		return ""
	}
	n := leUint64(b)
	if n < 116444736000000000 {
		return ""
	}
	unixNs := int64(n-116444736000000000) * 100
	return time.Unix(0, unixNs).UTC().Format(time.RFC3339)
}

func usnRecordFieldOffsets(major uint16) (usnOff, reasonOff, nameLenOff, nameOffOff int, ok bool) {
	switch major {
	case 2:
		return 24, 40, 56, 58, true
	case 3, 4:
		return 40, 56, 72, 74, true
	default:
		return 0, 0, 0, 0, false
	}
}

func usnEventsLookInvalid(events []map[string]any) bool {
	if len(events) == 0 {
		return true
	}
	bad := 0
	for _, ev := range events {
		name, _ := ev["fileName"].(string)
		usn, _ := ev["usn"].(string)
		if !looksLikeUsnFileName(name) {
			bad++
			continue
		}
		if !looksLikeUsnValue(usn) {
			bad++
		}
	}
	return bad*2 >= len(events)
}

func looksLikeUsnValue(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || strings.Contains(s, "|") {
		return false
	}
	if strings.HasPrefix(s, "ref:") {
		return len(s) > 4
	}
	lower := strings.ToLower(s)
	if lower == "reason" || lower == "usn" {
		return false
	}
	if strings.HasPrefix(lower, "0x") {
		hexDigits := len(s) - 2
		if hexDigits < 8 || hexDigits > 16 {
			return false
		}
		trimmed := strings.TrimLeft(strings.ToLower(s[2:]), "0")
		return trimmed != ""
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) >= 8
}

func looksLikeUsnFileName(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	lower := strings.ToLower(s)
	switch lower {
	case "0x00000000", "reason", "time stamp", "file name", "usn":
		return false
	}
	if strings.HasPrefix(lower, "source info") {
		return false
	}
	if lower == "0x00000000" {
		return false
	}
	return true
}

type fsutilCSVMap struct {
	usn, timestamp, reason, fileName int
}

func parseFsutilCSVHeader(line string) fsutilCSVMap {
	cols, err := parseCSVFields(line)
	if err != nil {
		return fsutilCSVMap{usn: 4, timestamp: 5, reason: 6, fileName: 10}
	}
	idx := func(names ...string) int {
		for i, col := range cols {
			lower := strings.ToLower(strings.Trim(strings.TrimSpace(col), `"`))
			for _, name := range names {
				if lower == name || strings.Contains(lower, name) {
					return i
				}
			}
		}
		return -1
	}
	m := fsutilCSVMap{
		usn:       idx("usn"),
		timestamp: idx("timestamp", "time stamp"),
		reason:    idx("reason"),
		fileName:  idx("file name"),
	}
	if m.usn < 0 {
		m.usn = 4
	}
	if m.timestamp < 0 {
		m.timestamp = 5
	}
	if m.reason < 0 {
		m.reason = 6
	}
	if m.fileName < 0 {
		m.fileName = len(cols) - 1
		if m.fileName < 0 {
			m.fileName = 10
		}
	}
	return m
}

func parseCSVFields(line string) ([]string, error) {
	r := csv.NewReader(strings.NewReader(line))
	r.LazyQuotes = true
	return r.Read()
}

func readUsnRecordsFsutil(volume string, startUsnHex string, maxEvents int) ([]map[string]any, error) {
	vol := normalizeVolumeLetter(volume)
	startUsnHex = strings.TrimSpace(startUsnHex)
	if startUsnHex == "" {
		return nil, fmt.Errorf("empty startUsn")
	}
	startArg := "startusn=" + startUsnHex
	out, err := exec.Command("fsutil.exe", "usn", "readjournal", vol, "csv", startArg).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("fsutil usn readjournal: %w: %s", err, strings.TrimSpace(string(out)))
	}
	var events []map[string]any
	colMap := fsutilCSVMap{usn: 4, timestamp: 5, reason: 6, fileName: 10}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Major Version,") {
			colMap = parseFsutilCSVHeader(line)
			continue
		}
		cols, err := parseCSVFields(line)
		if err != nil || len(cols) < 8 {
			continue
		}
		ev := mapFsutilUsnRow(cols, colMap)
		if ev == nil {
			continue
		}
		events = append(events, ev)
		if len(events) >= maxEvents {
			break
		}
	}
	if len(events) == 0 {
		return nil, fmt.Errorf("fsutil readjournal returned 0 usable rows")
	}
	return events, nil
}

func mapFsutilUsnRow(cols []string, colMap fsutilCSVMap) map[string]any {
	get := func(i int) string {
		if i < 0 || i >= len(cols) {
			return ""
		}
		return strings.Trim(cols[i], `"`)
	}
	fileName := get(colMap.fileName)
	usnStr := get(colMap.usn)
	timestamp := get(colMap.timestamp)
	reasonRaw := get(colMap.reason)

	if !looksLikeUsnValue(usnStr) {
		usnStr = findUsnInColumns(cols)
	}
	if !looksLikeUsnFileName(fileName) {
		fileName = findFileNameInColumns(cols)
	}
	if !looksLikeUsnFileName(fileName) {
		return nil
	}
	if !looksLikeUsnValue(usnStr) {
		// Some fsutil builds omit Usn; use file reference as a stable key.
		if ref := findFileRefInColumns(cols); ref != "" {
			usnStr = "ref:" + ref
		} else {
			return nil
		}
	}
	fileRef := findFileRefInColumns(cols)
	if strings.Contains(get(colMap.usn), "|") {
		reasonRaw = get(colMap.usn)
	} else if strings.Contains(get(4), "|") {
		reasonRaw = get(4)
	}
	reasonLabelsOut, reasonCode := parseFsutilReason(reasonRaw)
	if strings.Contains(reasonRaw, "|") {
		reasonLabelsOut = splitReasonText(reasonRaw)
		reasonCode = ""
	}
	ev := map[string]any{
		"usn":        usnStr,
		"fileName":   fileName,
		"fileRef":    fileRef,
		"reason":     reasonLabelsOut,
		"reasonCode": reasonCode,
	}
	if timestamp != "" && !strings.EqualFold(timestamp, "time stamp") {
		ev["timestamp"] = timestamp
	}
	return ev
}

func findUsnInColumns(cols []string) string {
	for _, col := range cols {
		candidate := strings.Trim(col, `"`)
		if looksLikeFileRef(candidate) {
			continue
		}
		if looksLikeUsnValue(candidate) {
			return candidate
		}
	}
	return ""
}

func findFileNameInColumns(cols []string) string {
	for i := len(cols) - 1; i >= 0; i-- {
		candidate := strings.Trim(cols[i], `"`)
		if looksLikeUsnFileName(candidate) {
			return candidate
		}
	}
	return ""
}

func findFileRefInColumns(cols []string) string {
	for _, col := range cols {
		candidate := strings.Trim(col, `"`)
		if looksLikeFileRef(candidate) {
			return candidate
		}
	}
	return ""
}

func looksLikeFileRef(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(lower, "0x") && len(lower) > 18
}

func splitReasonText(reasonRaw string) []string {
	parts := strings.Split(reasonRaw, "|")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseFsutilReason(reasonRaw string) ([]string, string) {
	reasonRaw = strings.TrimSpace(reasonRaw)
	if reasonRaw == "" {
		return []string{"0x00000000"}, "0x00000000"
	}
	lower := strings.ToLower(reasonRaw)
	if strings.HasPrefix(lower, "0x") {
		var n uint64
		fmt.Sscanf(reasonRaw, "%x", &n)
		reason := uint32(n)
		return reasonLabels(reason), fmt.Sprintf("0x%08x", reason)
	}
	if strings.Contains(reasonRaw, "|") {
		parts := strings.Split(reasonRaw, "|")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		return out, ""
	}
	for flag, label := range usnReasonLabels {
		_ = flag
		if strings.EqualFold(reasonRaw, label) {
			return []string{label}, fmt.Sprintf("0x%08x", flag)
		}
	}
	return []string{reasonRaw}, ""
}

func stringutf16(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return windows.UTF16ToString(u16)
}

func reasonLabels(reason uint32) []string {
	var out []string
	for flag, label := range usnReasonLabels {
		if reason&flag != 0 {
			out = append(out, label)
		}
	}
	if len(out) == 0 {
		out = append(out, fmt.Sprintf("0x%08x", reason))
	}
	return out
}

var _ = unsafe.Pointer(nil)
