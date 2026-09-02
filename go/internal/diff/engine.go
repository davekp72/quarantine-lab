package diff

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/quarantine-lab/quarantine/internal/evidence"
)

// Result matches manifest viewer diff JSON schema.
type Result struct {
	Meta    MetaSection    `json:"meta"`
	Summary SummarySection `json:"summary"`
	Files   FilesSection   `json:"files"`
	Registry RegistrySection `json:"registry"`
	Tasks   TasksSection   `json:"tasks"`
	Sysmon  SysmonSection  `json:"sysmon"`
	ServiceInstalls ServiceInstallsSection `json:"serviceInstalls"`
	USN     *USNSection    `json:"usn,omitempty"`
	Network *NetworkSection `json:"network,omitempty"`
}

type MetaSection struct {
	FromManifest         string   `json:"fromManifest"`
	ToManifest           string   `json:"toManifest"`
	FromSnapshot         string   `json:"fromSnapshot"`
	ToSnapshot           string   `json:"toSnapshot"`
	FromCaptured         string   `json:"fromCaptured"`
	ToCaptured           string   `json:"toCaptured"`
	FromComputer         string   `json:"fromComputer"`
	ToComputer           string   `json:"toComputer"`
	FromFileCount        int      `json:"fromFileCount"`
	ToFileCount          int      `json:"toFileCount"`
	FromScanMode         string   `json:"fromScanMode"`
	ToScanMode           string   `json:"toScanMode"`
	FileDiffSource       string   `json:"fileDiffSource"`
	RegistryDiffSource   string   `json:"registryDiffSource"`
	FromUserRegistryCount int     `json:"fromUserRegistryCount"`
	ToUserRegistryCount   int     `json:"toUserRegistryCount"`
	CompareMode          string   `json:"compareMode"`
	Warnings             []string `json:"warnings"`
}

type SummarySection struct {
	FilesAdded             int    `json:"filesAdded"`
	FilesRemoved           int    `json:"filesRemoved"`
	FilesModified          int    `json:"filesModified"`
	RegistryAdded          int    `json:"registryAdded"`
	RegistryRemoved        int    `json:"registryRemoved"`
	RegistryModified       int    `json:"registryModified"`
	RegistryVolatileFiltered int  `json:"registryVolatileFiltered"`
	RegistryDiffSource     string `json:"registryDiffSource"`
	TasksAdded             int    `json:"tasksAdded"`
	TasksRemoved           int    `json:"tasksRemoved"`
	TasksModified          int    `json:"tasksModified"`
	TasksVolatileOnly      int    `json:"tasksVolatileOnly"`
	SysmonAdded            int    `json:"sysmonAdded"`
	ServiceInstallsAdded   int    `json:"serviceInstallsAdded"`
	DNSQueries             int    `json:"dnsQueries"`
	NetworkRequests        int    `json:"networkRequests"`
	FileDiffSource         string `json:"fileDiffSource"`
}

type FilesSection struct {
	Added    []FileDetail `json:"added"`
	Removed  []FileDetail `json:"removed"`
	Modified []FileModified `json:"modified"`
}

type FileDetail struct {
	Path  string `json:"path"`
	Size  int64  `json:"size,omitempty"`
	Hash  string `json:"hash,omitempty"`
	Mtime string `json:"mtime,omitempty"`
	Src   string `json:"src,omitempty"`
	Change string `json:"change,omitempty"`
}

type FileModified struct {
	Path   string     `json:"path"`
	Before FileDetail `json:"before"`
	After  FileDetail `json:"after"`
}

type RegistrySection struct {
	Added    []evidence.RegistryEntry `json:"added"`
	Removed  []evidence.RegistryEntry `json:"removed"`
	Modified []RegistryModified       `json:"modified"`
}

type RegistryModified struct {
	Key      string `json:"key"`
	Name     string `json:"name"`
	Before   any    `json:"before"`
	After    any    `json:"after"`
	BeforeType string `json:"beforeType,omitempty"`
	AfterType  string `json:"afterType,omitempty"`
}

type TasksSection struct {
	Added        []map[string]any `json:"added"`
	Removed      []map[string]any `json:"removed"`
	Modified     []map[string]any `json:"modified"`
	VolatileOnly []map[string]any `json:"volatileOnly"`
}

type SysmonSection struct {
	Available  bool             `json:"available"`
	Message    string           `json:"message"`
	BaselineAt string           `json:"baselineAt"`
	RecordedAt string           `json:"recordedAt"`
	Added      []map[string]any `json:"added"`
}

type ServiceInstallsSection struct {
	Available  bool             `json:"available"`
	Message    string           `json:"message"`
	BaselineAt string           `json:"baselineAt"`
	RecordedAt string           `json:"recordedAt"`
	Added      []map[string]any `json:"added"`
}

type USNSection struct {
	Available  bool             `json:"available"`
	Message    string           `json:"message"`
	Volume     string           `json:"volume"`
	BaselineAt string           `json:"baselineAt"`
	RecordedAt string           `json:"recordedAt"`
	Truncated  bool             `json:"truncated"`
	EventCount int              `json:"eventCount"`
	Events     []map[string]any `json:"events"`
}

type NetworkSection struct {
	Available  bool             `json:"available"`
	Message    string           `json:"message"`
	WindowFrom string           `json:"windowFrom"`
	WindowTo   string           `json:"windowTo"`
	Sources    map[string]any   `json:"sources"`
	DNS        []map[string]any `json:"dns"`
	Requests   []map[string]any `json:"requests"`
	Truncated  bool             `json:"truncated"`
}

// Compare builds diff from two manifests.
func Compare(fromPath, toPath string, left, right *evidence.Manifest) (*Result, error) {
	if left == nil || right == nil {
		return nil, fmt.Errorf("manifests required")
	}

	leftFiles := indexFiles(left.Files)
	rightFiles := indexFiles(right.Files)

	added, removed, modified := diffFiles(leftFiles, rightFiles)
	addedReg, removedReg, modifiedReg, volatileFiltered := diffRegistry(left.Registry, right.Registry)

	fileDiffSource := "manifest-scanned"
	if left.ScanMode == "events" || right.ScanMode == "events" {
		fileDiffSource = "events"
		eventAdded, eventRemoved, eventModified := diffEventFiles(left, right)
		if len(added)+len(removed)+len(modified) == 0 {
			added, removed, modified = eventAdded, eventRemoved, eventModified
			fileDiffSource = "usn-sysmon"
		}
	}

	added, removed, modified = filterUSNLeafFiles(added, removed, modified)

	compareMode := "baseline-to-evidence"
	if left.Snapshot != "" && right.Snapshot != "" {
		compareMode = "snapshot-pair"
	}

	addedSysmon := diffSysmonEvents(left.Sysmon, right.Sysmon)
	addedSvc := diffServiceInstalls(left.ServiceInstalls, right.ServiceInstalls)
	addedUsn, usnSection := diffUSN(left, right, compareMode)

	res := &Result{
		Meta: MetaSection{
			FromManifest:          fromPath,
			ToManifest:            toPath,
			FromSnapshot:          left.Snapshot,
			ToSnapshot:            right.Snapshot,
			FromCaptured:          left.CapturedAt,
			ToCaptured:            right.CapturedAt,
			FromComputer:          left.ComputerName,
			ToComputer:            right.ComputerName,
			FromFileCount:         len(left.Files),
			ToFileCount:           len(right.Files),
			FromScanMode:          scanMode(left),
			ToScanMode:            scanMode(right),
			FileDiffSource:        fileDiffSource,
			RegistryDiffSource:    "manifest",
			FromUserRegistryCount: countHKU(left.Registry),
			ToUserRegistryCount:   countHKU(right.Registry),
			CompareMode:           compareMode,
			Warnings:              []string{},
		},
		Summary: SummarySection{
			FilesAdded:               len(added),
			FilesRemoved:             len(removed),
			FilesModified:            len(modified),
			RegistryAdded:            len(addedReg),
			RegistryRemoved:          len(removedReg),
			RegistryModified:         len(modifiedReg),
			RegistryVolatileFiltered: volatileFiltered,
			RegistryDiffSource:       "manifest",
			FileDiffSource:           fileDiffSource,
			SysmonAdded:              len(addedSysmon),
			ServiceInstallsAdded:     len(addedSvc),
		},
		Files: FilesSection{Added: added, Removed: removed, Modified: modified},
		Registry: RegistrySection{
			Added: addedReg, Removed: removedReg, Modified: modifiedReg,
		},
		Tasks: TasksSection{
			Added: []map[string]any{}, Removed: []map[string]any{},
			Modified: []map[string]any{}, VolatileOnly: []map[string]any{},
		},
		Sysmon: SysmonSection{
			Available:  len(right.Sysmon) > 0,
			BaselineAt: left.CapturedAt,
			RecordedAt: right.CapturedAt,
			Added:      addedSysmon,
		},
		ServiceInstalls: ServiceInstallsSection{
			Available:  len(right.ServiceInstalls) > 0,
			BaselineAt: left.CapturedAt,
			RecordedAt: right.CapturedAt,
			Added:      addedSvc,
		},
		USN: usnSection,
	}
	if usnSection != nil {
		res.Summary.SysmonAdded = len(addedSysmon)
		_ = addedUsn
	}
	return res, nil
}

func scanMode(m *evidence.Manifest) string {
	if m.ScanMode != "" {
		return m.ScanMode
	}
	if len(m.Files) == 0 {
		return "events"
	}
	return "full"
}

func indexFiles(files []evidence.FileEntry) map[string]evidence.FileEntry {
	out := make(map[string]evidence.FileEntry, len(files))
	for _, f := range files {
		p := strings.ToLower(f.PathValue())
		if p != "" {
			out[p] = f
		}
	}
	return out
}

func diffFiles(left, right map[string]evidence.FileEntry) (added []FileDetail, removed []FileDetail, modified []FileModified) {
	for p, f := range right {
		if _, ok := left[p]; !ok {
			added = append(added, fileDetail(f))
		}
	}
	for p, f := range left {
		if _, ok := right[p]; !ok {
			removed = append(removed, fileDetail(f))
		}
	}
	for p, rf := range right {
		lf, ok := left[p]
		if !ok {
			continue
		}
		if lf.H != rf.H || lf.S != rf.S {
			modified = append(modified, FileModified{
				Path: rf.PathValue(), Before: fileDetail(lf), After: fileDetail(rf),
			})
		}
	}
	sort.Slice(added, func(i, j int) bool { return added[i].Path < added[j].Path })
	sort.Slice(removed, func(i, j int) bool { return removed[i].Path < removed[j].Path })
	sort.Slice(modified, func(i, j int) bool { return modified[i].Path < modified[j].Path })
	return
}

func fileDetail(f evidence.FileEntry) FileDetail {
	return FileDetail{
		Path: f.PathValue(), Size: f.S, Hash: f.H, Mtime: f.M,
		Src: f.Src, Change: f.Change,
	}
}

func regKey(e evidence.RegistryEntry) string {
	return strings.ToLower(e.K) + "|" + strings.ToLower(e.N)
}

func diffRegistry(left, right []evidence.RegistryEntry) (added, removed []evidence.RegistryEntry, modified []RegistryModified, volatileFiltered int) {
	lidx := map[string]evidence.RegistryEntry{}
	for _, e := range left {
		lidx[regKey(e)] = e
	}
	ridx := map[string]evidence.RegistryEntry{}
	for _, e := range right {
		if isVolatileRegistry(e.K) {
			volatileFiltered++
			continue
		}
		ridx[regKey(e)] = e
	}
	for k, e := range ridx {
		if _, ok := lidx[k]; !ok {
			added = append(added, e)
		}
	}
	for k, e := range lidx {
		if isVolatileRegistry(e.K) {
			continue
		}
		if _, ok := ridx[k]; !ok {
			removed = append(removed, e)
		}
	}
	for k, re := range ridx {
		le, ok := lidx[k]
		if !ok {
			continue
		}
		if fmt.Sprint(le.V) != fmt.Sprint(re.V) || le.T != re.T {
			modified = append(modified, RegistryModified{
				Key: re.K, Name: re.N, Before: le.V, After: re.V,
				BeforeType: le.T, AfterType: re.T,
			})
		}
	}
	return
}

func isVolatileRegistry(key string) bool {
	patterns := []string{
		`\IrisService\Cache\`, `\TaskCache\Tasks\{`, `\Explorer\SessionInfo\`,
		`\ContentDeliveryManager\`, `\InstallService\State`, `\Volatile Environment\`,
	}
	for _, p := range patterns {
		if strings.Contains(key, p) {
			return true
		}
	}
	return false
}

func countHKU(entries []evidence.RegistryEntry) int {
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(strings.ToUpper(e.K), `HKU\`) {
			n++
		}
	}
	return n
}

func parseEventsSection(raw json.RawMessage) []map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var section map[string]any
	if err := json.Unmarshal(raw, &section); err != nil {
		return nil
	}
	if av, ok := section["available"].(bool); ok && !av {
		return nil
	}
	events, ok := section["events"].([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(events))
	for _, e := range events {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func eventKey(ev map[string]any, fields ...string) string {
	parts := make([]string, 0, len(fields))
	for _, f := range fields {
		if v, ok := ev[f]; ok {
			parts = append(parts, fmt.Sprint(v))
		}
	}
	return strings.Join(parts, "|")
}

func diffSysmonEvents(leftRaw, rightRaw json.RawMessage) []map[string]any {
	left := parseEventsSection(leftRaw)
	right := parseEventsSection(rightRaw)
	leftKeys := map[string]bool{}
	for _, ev := range left {
		leftKeys[eventKey(ev, "eid", "t", "image", "target", "targetObject", "commandLine", "queryName", "details", "summary", "id")] = true
	}
	var added []map[string]any
	for _, ev := range right {
		k := eventKey(ev, "eid", "t", "image", "target", "targetObject", "commandLine", "queryName", "details", "summary", "id")
		if !leftKeys[k] {
			added = append(added, ev)
		}
	}
	return added
}

func diffServiceInstalls(leftRaw, rightRaw json.RawMessage) []map[string]any {
	left := parseEventsSection(leftRaw)
	right := parseEventsSection(rightRaw)
	leftKeys := map[string]bool{}
	for _, ev := range left {
		leftKeys[eventKey(ev, "eid", "t", "serviceName", "imagePath", "summary", "id")] = true
	}
	var added []map[string]any
	for _, ev := range right {
		k := eventKey(ev, "eid", "t", "serviceName", "imagePath", "summary", "id")
		if !leftKeys[k] {
			added = append(added, ev)
		}
	}
	return added
}

func diffUSN(left, right *evidence.Manifest, compareMode string) ([]map[string]any, *USNSection) {
	leftEvents := parseEventsSection(left.USN)
	rightEvents := parseEventsSection(right.USN)
	leftKeys := map[string]bool{}
	for _, ev := range leftEvents {
		leftKeys[eventKey(ev, "usn", "timestamp", "fileName")] = true
	}
	var added []map[string]any
	for _, ev := range rightEvents {
		k := eventKey(ev, "usn", "timestamp", "fileName")
		if !leftKeys[k] {
			added = append(added, ev)
		}
	}
	if len(right.USN) == 0 {
		return added, nil
	}
	msg := ""
	if compareMode == "snapshot-pair" {
		msg = fmt.Sprintf("USN events in To not in From (%s → %s).", left.Snapshot, right.Snapshot)
	}
	return added, &USNSection{
		Available:  true,
		Message:    msg,
		Volume:     "C:",
		BaselineAt: left.CapturedAt,
		RecordedAt: right.CapturedAt,
		EventCount: len(added),
		Events:     added,
	}
}

func diffEventFiles(left, right *evidence.Manifest) (added []FileDetail, removed []FileDetail, modified []FileModified) {
	pathKinds := map[string]string{}
	addPath := func(path, kind string) {
		if path == "" {
			return
		}
		p := strings.ToLower(path)
		if kind == "removed" {
			pathKinds[p] = "removed"
		} else if _, ok := pathKinds[p]; !ok {
			pathKinds[p] = kind
		}
	}
	for _, ev := range parseEventsSection(right.USN) {
		addPath(resolveUSNPath(ev), usnKind(ev))
	}
	for _, ev := range parseEventsSection(right.Sysmon) {
		eid, _ := ev["eid"].(float64)
		target, _ := ev["target"].(string)
		if target == "" {
			continue
		}
		kind := "added"
		if int(eid) == 23 || int(eid) == 26 {
			kind = "removed"
		}
		addPath(target, kind)
	}
	for path, kind := range pathKinds {
		switch kind {
		case "added":
			added = append(added, FileDetail{Path: path, Change: kind, Src: "events"})
		case "removed":
			removed = append(removed, FileDetail{Path: path, Change: kind, Src: "events"})
		default:
			modified = append(modified, FileModified{
				Path: path,
				After: FileDetail{Path: path, Change: kind, Src: "events"},
			})
		}
	}
	sort.Slice(added, func(i, j int) bool { return added[i].Path < added[j].Path })
	sort.Slice(removed, func(i, j int) bool { return removed[i].Path < removed[j].Path })
	sort.Slice(modified, func(i, j int) bool { return modified[i].Path < modified[j].Path })
	return
}

func resolveUSNPath(ev map[string]any) string {
	if p, _ := ev["path"].(string); p != "" {
		return p
	}
	name, _ := ev["fileName"].(string)
	if name == "" {
		return ""
	}
	if len(name) >= 3 && name[1] == ':' {
		return name
	}
	if strings.HasPrefix(name, `\`) {
		return "C:" + name
	}
	if strings.HasSuffix(strings.ToLower(name), `\hosts`) || strings.HasSuffix(strings.ToLower(name), "hosts") {
		return `C:\Windows\System32\drivers\etc\hosts`
	}
	return `C:\` + name
}

func usnKind(ev map[string]any) string {
	for _, r := range usnReasonStrings(ev) {
		if usnReasonMatches(r, "file_delete", "delete") {
			return "removed"
		}
	}
	for _, r := range usnReasonStrings(ev) {
		if usnReasonMatches(r, "file_create", "rename_new_name", "create") {
			return "added"
		}
	}
	return "modified"
}

func usnReasonStrings(ev map[string]any) []string {
	raw, ok := ev["reason"]
	if !ok {
		raw = ev["reasons"]
	}
	switch v := raw.(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			out = append(out, fmt.Sprint(item))
		}
		return out
	case []string:
		return v
	default:
		return nil
	}
}

func usnReasonMatches(reason string, keys ...string) bool {
	norm := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(reason), " ", "_"))
	for _, key := range keys {
		if norm == key || strings.Contains(norm, key) {
			return true
		}
	}
	return false
}
