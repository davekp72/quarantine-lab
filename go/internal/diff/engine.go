package diff

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/quarantine-lab/quarantine/internal/agent/collectors"
	"github.com/quarantine-lab/quarantine/internal/evidence"
	"github.com/quarantine-lab/quarantine/internal/registry"
)

// Result matches manifest viewer diff JSON schema.
type Result struct {
	Meta            MetaSection            `json:"meta"`
	Summary         SummarySection         `json:"summary"`
	Files           FilesSection           `json:"files"`
	Registry        RegistrySection        `json:"registry"`
	Tasks           TasksSection           `json:"tasks"`
	Sysmon          SysmonSection          `json:"sysmon"`
	ServiceInstalls ServiceInstallsSection `json:"serviceInstalls"`
	USN             *USNSection            `json:"usn,omitempty"`
	Network         *NetworkSection        `json:"network,omitempty"`
}

type MetaSection struct {
	FromManifest          string   `json:"fromManifest"`
	ToManifest            string   `json:"toManifest"`
	FromSnapshot          string   `json:"fromSnapshot"`
	ToSnapshot            string   `json:"toSnapshot"`
	FromCaptured          string   `json:"fromCaptured"`
	ToCaptured            string   `json:"toCaptured"`
	FromComputer          string   `json:"fromComputer"`
	ToComputer            string   `json:"toComputer"`
	FromFileCount         int      `json:"fromFileCount"`
	ToFileCount           int      `json:"toFileCount"`
	FromScanMode          string   `json:"fromScanMode"`
	ToScanMode            string   `json:"toScanMode"`
	FileDiffSource        string   `json:"fileDiffSource"`
	RegistryDiffSource    string   `json:"registryDiffSource"`
	FromUserRegistryCount int      `json:"fromUserRegistryCount"`
	ToUserRegistryCount   int      `json:"toUserRegistryCount"`
	CompareMode           string   `json:"compareMode"`
	Warnings              []string `json:"warnings"`
}

type SummarySection struct {
	FilesAdded               int    `json:"filesAdded"`
	FilesRemoved             int    `json:"filesRemoved"`
	FilesModified            int    `json:"filesModified"`
	RegistryAdded            int    `json:"registryAdded"`
	RegistryRemoved          int    `json:"registryRemoved"`
	RegistryModified         int    `json:"registryModified"`
	RegistryVolatileFiltered int    `json:"registryVolatileFiltered"`
	RegistryDiffSource       string `json:"registryDiffSource"`
	TasksAdded               int    `json:"tasksAdded"`
	TasksRemoved             int    `json:"tasksRemoved"`
	TasksModified            int    `json:"tasksModified"`
	TasksVolatileOnly        int    `json:"tasksVolatileOnly"`
	SysmonAdded              int    `json:"sysmonAdded"`
	ServiceInstallsAdded     int    `json:"serviceInstallsAdded"`
	DNSQueries               int    `json:"dnsQueries"`
	NetworkRequests          int    `json:"networkRequests"`
	FileDiffSource           string `json:"fileDiffSource"`
}

type FilesSection struct {
	Added    []FileDetail   `json:"added"`
	Removed  []FileDetail   `json:"removed"`
	Modified []FileModified `json:"modified"`
}

type FileDetail struct {
	Path   string `json:"path"`
	Size   int64  `json:"size,omitempty"`
	Hash   string `json:"hash,omitempty"`
	Mtime  string `json:"mtime,omitempty"`
	Src    string `json:"src,omitempty"`
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
	Key        string `json:"key"`
	Name       string `json:"name"`
	Before     any    `json:"before"`
	After      any    `json:"after"`
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
	addedReg, removedReg, modifiedReg, regWarnings := suppressFalseHKCUDiff(left, right, addedReg, removedReg, modifiedReg)
	registryDiffSource := "manifest"

	fileDiffSource := "manifest-scanned"
	if left.ScanMode == "events" || right.ScanMode == "events" {
		fileDiffSource = "events"
		if len(left.Files) == 0 && len(right.Files) > 0 {
			added, removed, modified = filesFromCapturedChanges(right.Files)
		} else if len(added)+len(removed)+len(modified) == 0 {
			added, removed, modified = diffEventFiles(left, right)
			fileDiffSource = "usn-sysmon"
		}
	}

	added, removed, modified = filterUSNLeafFiles(added, removed, modified)
	added, removed, modified = filterNoisyDiffFiles(added, removed, modified)

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
			RegistryDiffSource:    registryDiffSource,
			FromUserRegistryCount: countHKU(left.Registry),
			ToUserRegistryCount:   countHKU(right.Registry),
			CompareMode:           compareMode,
			Warnings:              append([]string{}, regWarnings...),
		},
		Summary: SummarySection{
			FilesAdded:               len(added),
			FilesRemoved:             len(removed),
			FilesModified:            len(modified),
			RegistryAdded:            len(addedReg),
			RegistryRemoved:          len(removedReg),
			RegistryModified:         len(modifiedReg),
			RegistryVolatileFiltered: volatileFiltered,
			RegistryDiffSource:       registryDiffSource,
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

// ApplyHiveRegistryDiff replaces manifest registry delta with a hive-index merge-join.
func ApplyHiveRegistryDiff(res *Result, fromIndex, toIndex string, fromMeta, toMeta *registry.IndexMeta, fromHives, toHives []registry.LocalHiveFile) error {
	if res == nil {
		return fmt.Errorf("result required")
	}
	idiff, err := registry.DiffIndexes(fromIndex, toIndex)
	if err != nil {
		return err
	}
	if len(fromHives) > 0 || len(toHives) > 0 {
		registry.HydrateRecordValues(toHives, idiff.Added)
		registry.HydrateRecordValues(fromHives, idiff.Removed)
		registry.HydrateValueChanges(fromHives, toHives, idiff.Modified)
	}
	added := make([]evidence.RegistryEntry, 0, len(idiff.Added))
	for _, r := range idiff.Added {
		added = append(added, indexToEntry(r))
	}
	removed := make([]evidence.RegistryEntry, 0, len(idiff.Removed))
	for _, r := range idiff.Removed {
		removed = append(removed, indexToEntry(r))
	}
	modified := make([]RegistryModified, 0, len(idiff.Modified))
	for _, m := range idiff.Modified {
		before := m.V0
		after := m.V1
		if before == nil && m.H0 != "" {
			before = fmt.Sprintf("sha256:%s", m.H0)
			if m.S0 > 0 {
				before = fmt.Sprintf("sha256:%s (%d bytes)", m.H0, m.S0)
			}
		}
		if after == nil && m.H1 != "" {
			after = fmt.Sprintf("sha256:%s", m.H1)
			if m.S1 > 0 {
				after = fmt.Sprintf("sha256:%s (%d bytes)", m.H1, m.S1)
			}
		}
		modified = append(modified, RegistryModified{
			Key: m.K, Name: m.N, Before: before, After: after, AfterType: m.T,
		})
	}
	res.Registry = RegistrySection{Added: added, Removed: removed, Modified: modified}
	res.Meta.RegistryDiffSource = "hive-index"
	res.Summary.RegistryDiffSource = "hive-index"
	res.Summary.RegistryAdded = len(added)
	res.Summary.RegistryRemoved = len(removed)
	res.Summary.RegistryModified = len(modified)
	res.Summary.RegistryVolatileFiltered = 0
	// Drop manifest-era HKCU false-positive warnings; hive indexes are authoritative.
	res.Meta.Warnings = nil
	if fromMeta != nil {
		res.Meta.FromUserRegistryCount = fromMeta.EntryCount
		res.Meta.Warnings = append(res.Meta.Warnings, fromMeta.Warnings...)
	}
	if toMeta != nil {
		res.Meta.ToUserRegistryCount = toMeta.EntryCount
		res.Meta.Warnings = append(res.Meta.Warnings, toMeta.Warnings...)
	}
	return nil
}

func indexToEntry(r registry.IndexRecord) evidence.RegistryEntry {
	v := r.V
	if v == nil && r.H != "" {
		if r.Size > 0 {
			v = fmt.Sprintf("sha256:%s (%d bytes)", r.H, r.Size)
		} else {
			v = fmt.Sprintf("sha256:%s", r.H)
		}
	}
	return evidence.RegistryEntry{K: r.K, N: r.N, T: r.T, V: v}
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

func capturedFilePresent(f evidence.FileEntry) bool {
	if f.H != "" || f.S > 0 {
		return true
	}
	switch strings.ToLower(f.C) {
	case "text", "base64":
		return true
	}
	return false
}

func filesFromCapturedChanges(files []evidence.FileEntry) (added []FileDetail, removed []FileDetail, modified []FileModified) {
	for _, f := range files {
		p := f.PathValue()
		if p == "" {
			continue
		}
		if collectors.ClassifyFileNoise(p, "") != "" {
			continue
		}
		d := fileDetail(f)
		change := strings.ToLower(f.Change)
		if change == "removed" && capturedFilePresent(f) {
			// USN ReplaceFile/recreate was labeled deleted even though the guest still had the file.
			change = "added"
			d.Change = "added"
		}
		switch change {
		case "removed":
			removed = append(removed, d)
		case "modified":
			modified = append(modified, FileModified{Path: p, After: d})
		default:
			added = append(added, d)
		}
	}
	sort.Slice(added, func(i, j int) bool { return added[i].Path < added[j].Path })
	sort.Slice(removed, func(i, j int) bool { return removed[i].Path < removed[j].Path })
	sort.Slice(modified, func(i, j int) bool { return modified[i].Path < modified[j].Path })
	return
}

func filterNoisyDiffFiles(added []FileDetail, removed []FileDetail, modified []FileModified) ([]FileDetail, []FileDetail, []FileModified) {
	fa := added[:0]
	for _, f := range added {
		if collectors.ClassifyFileNoise(f.Path, "") == "" {
			fa = append(fa, f)
		}
	}
	fr := removed[:0]
	for _, f := range removed {
		if collectors.ClassifyFileNoise(f.Path, "") == "" {
			fr = append(fr, f)
		}
	}
	fm := modified[:0]
	for _, f := range modified {
		if collectors.ClassifyFileNoise(f.Path, "") == "" {
			fm = append(fm, f)
		}
	}
	return fa, fr, fm
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
		if strings.HasPrefix(strings.ToUpper(e.K), `HKU\`) || strings.HasPrefix(strings.ToUpper(e.K), `HKU:`) {
			n++
		}
	}
	return n
}

func isHKUKey(key string) bool {
	u := strings.ToUpper(key)
	return strings.HasPrefix(u, `HKU\`) || strings.HasPrefix(u, `HKU:`)
}

func isInteractiveUserHKU(key string) bool {
	u := strings.ToUpper(strings.ReplaceAll(key, `/`, `\`))
	return strings.Contains(u, `HKU:\S-1-5-21-`) || strings.Contains(u, `HKU\S-1-5-21-`)
}

func countInteractiveHKU(entries []evidence.RegistryEntry) int {
	n := 0
	for _, e := range entries {
		if isInteractiveUserHKU(e.K) {
			n++
		}
	}
	return n
}

// hkcuCaptureFailed reports that user-hive capture did not succeed for this manifest.
func hkcuCaptureFailed(m *evidence.Manifest) bool {
	if m == nil {
		return false
	}
	if len(m.UserRegistryWarn) > 0 {
		return true
	}
	return false
}

// suppressFalseHKCUDiff drops mass interactive-user HKU add/remove noise when one side failed to capture HKCU.
// Shared hives (.DEFAULT, SYSTEM) are left intact.
func suppressFalseHKCUDiff(
	left, right *evidence.Manifest,
	added, removed []evidence.RegistryEntry,
	modified []RegistryModified,
) ([]evidence.RegistryEntry, []evidence.RegistryEntry, []RegistryModified, []string) {
	var warnings []string
	leftFail := hkcuCaptureFailed(left)
	rightFail := hkcuCaptureFailed(right)
	leftHKU := countInteractiveHKU(left.Registry)
	rightHKU := countInteractiveHKU(right.Registry)

	if !rightFail && rightHKU == 0 && leftHKU >= 50 {
		rightFail = true
		warnings = append(warnings,
			fmt.Sprintf("Payload HKCU absent on To (%s) while From has %d user entries — treating as capture miss, not mass delete",
				right.Snapshot, leftHKU))
	}
	if !leftFail && leftHKU == 0 && rightHKU >= 50 {
		leftFail = true
		warnings = append(warnings,
			fmt.Sprintf("Payload HKCU absent on From (%s) while To has %d user entries — treating as capture miss, not mass add",
				left.Snapshot, rightHKU))
	}

	if rightFail && leftHKU > 0 {
		before := len(removed)
		removed = filterRegistryEntries(removed, func(e evidence.RegistryEntry) bool { return !isInteractiveUserHKU(e.K) })
		if n := before - len(removed); n > 0 {
			warnings = append(warnings,
				fmt.Sprintf("Suppressed %d false payload-HKCU removals (To snapshot HKCU capture unavailable)", n))
		}
		modified = filterRegistryModified(modified, func(m RegistryModified) bool { return !isInteractiveUserHKU(m.Key) })
	}
	if leftFail && rightHKU > 0 {
		before := len(added)
		added = filterRegistryEntries(added, func(e evidence.RegistryEntry) bool { return !isInteractiveUserHKU(e.K) })
		if n := before - len(added); n > 0 {
			warnings = append(warnings,
				fmt.Sprintf("Suppressed %d false payload-HKCU additions (From snapshot HKCU capture unavailable)", n))
		}
		modified = filterRegistryModified(modified, func(m RegistryModified) bool { return !isInteractiveUserHKU(m.Key) })
	}
	if leftFail && len(left.UserRegistryWarn) > 0 {
		warnings = append(warnings, "From snapshot: "+strings.Join(left.UserRegistryWarn, "; "))
	}
	if rightFail && len(right.UserRegistryWarn) > 0 {
		warnings = append(warnings, "To snapshot: "+strings.Join(right.UserRegistryWarn, "; "))
	}
	return added, removed, modified, uniqueStrings(warnings)
}

func filterRegistryEntries(in []evidence.RegistryEntry, keep func(evidence.RegistryEntry) bool) []evidence.RegistryEntry {
	out := make([]evidence.RegistryEntry, 0, len(in))
	for _, e := range in {
		if keep(e) {
			out = append(out, e)
		}
	}
	return out
}

func filterRegistryModified(in []RegistryModified, keep func(RegistryModified) bool) []RegistryModified {
	out := make([]RegistryModified, 0, len(in))
	for _, e := range in {
		if keep(e) {
			out = append(out, e)
		}
	}
	return out
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
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
	for _, ev := range parseEventsSection(right.Sysmon) {
		eid, _ := ev["eid"].(float64)
		typ, _ := ev["t"].(string)
		kind, isFile := collectors.SysmonFileChangeKind(int(eid), typ)
		if !isFile {
			continue
		}
		target, _ := ev["target"].(string)
		if target == "" {
			target, _ = ev["targetFilename"].(string)
		}
		if target == "" {
			continue
		}
		collectors.MergeFileChangeKind(pathKinds, target, kind)
	}
	for _, ev := range parseEventsSection(right.USN) {
		path := resolveUSNPath(ev)
		if path == "" || IsUnresolvedUSNLeafPath(path) {
			continue
		}
		kind := usnKind(ev)
		if c, _ := ev["change"].(string); c != "" {
			kind = c
		}
		collectors.MergeFileChangeKind(pathKinds, path, kind)
	}
	for path, kind := range pathKinds {
		if collectors.ClassifyFileNoise(path, "") != "" {
			continue
		}
		switch kind {
		case "added":
			added = append(added, FileDetail{Path: path, Change: kind, Src: "events"})
		case "removed":
			removed = append(removed, FileDetail{Path: path, Change: kind, Src: "events"})
		default:
			modified = append(modified, FileModified{
				Path:  path,
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
	if strings.EqualFold(name, "hosts") || strings.HasSuffix(strings.ToLower(name), `\hosts`) {
		return `C:\Windows\System32\drivers\etc\hosts`
	}
	return ""
}

func usnKind(ev map[string]any) string {
	var hasDelete, hasCreate bool
	for _, r := range usnReasonStrings(ev) {
		if usnReasonMatches(r, "file_create", "rename_new_name") {
			hasCreate = true
		}
		if usnReasonMatches(r, "file_delete", "rename_old_name") {
			hasDelete = true
		}
	}
	if hasCreate {
		return "added"
	}
	if hasDelete {
		return "removed"
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
