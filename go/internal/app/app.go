package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	agenttypes "github.com/quarantine-lab/quarantine/internal/agent/types"
	"github.com/quarantine-lab/quarantine/internal/applog"
	"github.com/quarantine-lab/quarantine/internal/capture"
	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/diff"
	"github.com/quarantine-lab/quarantine/internal/disk"
	"github.com/quarantine-lab/quarantine/internal/evidence"
	"github.com/quarantine-lab/quarantine/internal/gateway"
	"github.com/quarantine-lab/quarantine/internal/inbox"
	"github.com/quarantine-lab/quarantine/internal/network"
	"github.com/quarantine-lab/quarantine/internal/proxy"
	"github.com/quarantine-lab/quarantine/internal/registry"
	"github.com/quarantine-lab/quarantine/internal/vbox"
	"github.com/quarantine-lab/quarantine/internal/vm"
)

// App is the central application facade for CLI and Wails.
type App struct {
	ConfigPath   string
	Cfg          *config.Config
	VM           *vm.Service
	Evidence     *evidence.Service
	Network      *network.Service
	Proxy        *proxy.Manager
	Capture      *capture.Manager
	Gateway      *gateway.Manager
	Inbox        *inbox.Service
	Disk         *disk.Reader
	WailsCtx     context.Context
	LastDiffPath string
	Log          *applog.Buffer
}

// New loads config and services.
func New(configPath string) (*App, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}
	vms, err := vm.NewService(configPath)
	if err != nil {
		return nil, err
	}
	ev, err := evidence.NewService(configPath)
	if err != nil {
		return nil, err
	}
	root := config.ProjectRoot(configPath)
	dr, _ := disk.NewReader(cfg, vms.VBox)
	gw := gateway.New(cfg, vms.VBox, root)
	capMgr := capture.New(cfg, vms.VBox)
	capMgr.Gateway = gw
	netSvc := network.New(cfg, vms.VBox)
	netSvc.Gateway = gw
	netSvc.CfgPath = configPath
	a := &App{
		ConfigPath: configPath,
		Cfg:        cfg,
		VM:         vms,
		Evidence:   ev,
		Network:    netSvc,
		Proxy:      proxy.New(cfg, root),
		Capture:    capMgr,
		Gateway:    gw,
		Inbox:      inbox.New(cfg, vms.VBox),
		Disk:       dr,
		Log:        applog.New(1000),
	}
	a.wireLogging()
	return a, nil
}

// CompareSnapshots builds diff JSON for a snapshot pair.
func (a *App) CompareSnapshots(ctx context.Context, fromSnap, toSnap string, refresh bool) (*diff.Result, string, error) {
	from := a.Cfg.ResolveSnapshotName(fromSnap)
	to := a.Cfg.ResolveSnapshotName(toSnap)
	if refresh {
		if err := a.ensureManifestPublished(from); err != nil {
			return nil, "", fmt.Errorf("publish from %s: %w", from, err)
		}
		if err := a.ensureManifestPublished(to); err != nil {
			return nil, "", fmt.Errorf("publish to %s: %w", to, err)
		}
	}
	left, err := a.Evidence.LoadManifest(from)
	if err != nil {
		return nil, "", err
	}
	right, err := a.Evidence.LoadManifest(to)
	if err != nil {
		return nil, "", err
	}
	a.enrichManifestHKCUWarnings(left, from)
	a.enrichManifestHKCUWarnings(right, to)
	fromPath := a.Cfg.ManifestPath(from)
	toPath := a.Cfg.ManifestPath(to)
	result, err := diff.Compare(fromPath, toPath, left, right)
	if err != nil {
		return nil, "", err
	}
	if err := a.applyHiveRegistryDiff(from, to, result); err != nil {
		a.logInfo("Hive registry index unavailable, using manifest registry: " + err.Error())
	}
	diff.EnrichNetwork(a.ConfigPath, config.ProjectRoot(a.ConfigPath), result, left.CapturedAt, right.CapturedAt, result.Sysmon.Added)
	outPath := a.Evidence.DiffOutputPath(from, to)
	raw, _ := json.MarshalIndent(result, "", "  ")
	if err := os.WriteFile(outPath, raw, 0o644); err != nil {
		return nil, "", err
	}
	return result, outPath, nil
}

// applyHiveRegistryDiff builds offline hive indexes when needed and prefers them over manifest registry.
func (a *App) applyHiveRegistryDiff(from, to string, result *diff.Result) error {
	if a.Evidence == nil || result == nil {
		return fmt.Errorf("evidence unavailable")
	}
	// Disk is only required when indexes must be built from snapshot RAW.
	if a.Disk == nil {
		if dr, err := disk.NewReader(a.Cfg, a.VM.VBox); err == nil {
			a.Disk = dr
		}
	} else if dr, err := disk.NewReader(a.Cfg, a.VM.VBox); err == nil {
		a.Disk = dr
	}
	a.logInfo("Building registry index for " + from + "…")
	fromMeta, err := a.ensureHiveIndex(from, false)
	if err != nil {
		return err
	}
	a.logInfo("Building registry index for " + to + "…")
	toMeta, err := a.ensureHiveIndex(to, false)
	if err != nil {
		return err
	}
	fromHives := localHiveFiles(a.Evidence, from)
	toHives := localHiveFiles(a.Evidence, to)
	return diff.ApplyHiveRegistryDiff(result,
		a.Evidence.RegistryIndexPath(from),
		a.Evidence.RegistryIndexPath(to),
		fromMeta, toMeta, fromHives, toHives)
}

func localHiveFiles(ev *evidence.Service, snap string) []registry.LocalHiveFile {
	if ev == nil {
		return nil
	}
	refs, err := ev.ListRegistryHiveFiles(snap)
	if err != nil {
		return nil
	}
	out := make([]registry.LocalHiveFile, 0, len(refs))
	for _, r := range refs {
		out = append(out, registry.LocalHiveFile{
			LocalPath: r.LocalPath, GuestPath: r.GuestPath, Prefix: r.Prefix,
		})
	}
	return out
}

func (a *App) ensureHiveIndex(snapshotName string, force bool) (*registry.IndexMeta, error) {
	indexPath := a.Evidence.RegistryIndexPath(snapshotName)
	metaPath := a.Evidence.RegistryIndexMetaPath(snapshotName)
	if !force && a.Evidence.RegistryHivesNewerThanIndex(snapshotName) {
		force = true
	}
	if !force && a.Evidence.HasRegistryIndex(snapshotName) {
		meta, err := registry.ReadIndexMeta(metaPath)
		if err != nil || meta == nil || meta.Format != registry.IndexFormatSlim {
			force = true
		} else {
			return meta, nil
		}
	}
	if force {
		a.Evidence.InvalidateRegistryIndex(snapshotName)
	}

	// Prefer live `reg save` hives pulled during capture (MB, not multi-GB RAW clone).
	if a.Evidence.HasRegistryHives(snapshotName) {
		a.logInfo("Building registry index from live hive dump for " + snapshotName + "…")
		refs, err := a.Evidence.ListRegistryHiveFiles(snapshotName)
		if err != nil {
			return nil, err
		}
		files := make([]registry.LocalHiveFile, 0, len(refs))
		for _, r := range refs {
			files = append(files, registry.LocalHiveFile{
				LocalPath: r.LocalPath, GuestPath: r.GuestPath, Prefix: r.Prefix,
			})
		}
		return registry.BuildIndexFromLocalHives(snapshotName, indexPath, metaPath, files)
	}

	if !a.Cfg.Manifest.RegistryDiskFlatten {
		return nil, fmt.Errorf("no live hive dump for %s (re-capture with agent 1.0.11+, or set manifest.registryDiskFlatten=true for slow RAW fallback)", snapshotName)
	}

	if a.Disk == nil {
		return nil, fmt.Errorf("disk reader required")
	}
	a.logInfo("WARNING: Flattening full snapshot disk to RAW for " + snapshotName + " (one-time, multi-GB). Prefer live hive dumps.")
	workDir, err := a.Evidence.EnsureRegistryIndexDir(snapshotName)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(workDir)
	return registry.BuildIndexFromDisk(a.Disk, snapshotName, indexPath, metaPath, workDir)
}

// enrichManifestHKCUWarnings loads payload sidecar warnings onto the manifest when missing.
func (a *App) enrichManifestHKCUWarnings(m *evidence.Manifest, snap string) {
	if m == nil || a.Evidence == nil {
		return
	}
	if len(m.UserRegistryWarn) > 0 {
		return
	}
	sc, err := a.Evidence.LoadSidecar(snap, "-payload-registry.json")
	if err != nil {
		return
	}
	if warns, ok := sc["warnings"].([]any); ok {
		for _, w := range warns {
			if s, ok := w.(string); ok && strings.TrimSpace(s) != "" {
				m.UserRegistryWarn = append(m.UserRegistryWarn, s)
			}
		}
	}
	hku := 0
	for _, e := range m.Registry {
		u := strings.ToUpper(e.K)
		if strings.HasPrefix(u, `HKU\`) || strings.HasPrefix(u, `HKU:`) {
			hku++
		}
	}
	if hku == 0 && len(m.UserRegistryWarn) == 0 {
		if ec, ok := sc["entryCount"].(float64); ok && ec == 0 {
			if sid, _ := sc["sid"].(string); sid == "" {
				m.UserRegistryWarn = append(m.UserRegistryWarn, "HKCU not captured (empty payload registry)")
			}
		}
	}
}

// ListSnapshots returns VBox snapshot list.
func (a *App) ListSnapshots(ctx context.Context) (any, error) {
	return a.VM.ListSnapshots(ctx)
}

// VMStatus returns VM status map.
func (a *App) VMStatus(ctx context.Context) (any, error) {
	return a.VM.Status(ctx)
}

// ReadSnapshotFile reads file content from sidecar capture or snapshot disk.
func (a *App) ReadSnapshotFile(snapshotName, guestPath string) (map[string]any, error) {
	if data, ok := a.Evidence.FileContentFromSidecar(snapshotName, guestPath); ok {
		return map[string]any{
			"path":    guestPath,
			"size":    len(data),
			"content": string(data),
			"base64":  false,
			"source":  "sidecar",
		}, nil
	}
	if entry, ok := a.Evidence.FileSidecarEntry(snapshotName, guestPath); ok && !evidence.FileCapturedInSidecar(entry) {
		return unavailableFilePreview(a.Evidence, snapshotName, guestPath, "events_only"), nil
	}
	if a.Disk == nil {
		return nil, fmt.Errorf("disk reader unavailable")
	}
	data, info, err := a.Disk.ReadFile(snapshotName, guestPath, 512*1024)
	if err != nil {
		if isDiskFileNotFound(err) {
			return unavailableFilePreview(a.Evidence, snapshotName, guestPath, "deleted_before_snapshot"), nil
		}
		return nil, err
	}
	return map[string]any{
		"path":    info.Path,
		"size":    info.Size,
		"content": string(data),
		"base64":  false,
		"source":  "disk",
	}, nil
}

func isDiskFileNotFound(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "not found")
}

func unavailableFilePreview(svc *evidence.Service, snapshotName, guestPath, reason string) map[string]any {
	meta := svc.FileCreateMetaFromSysmon(snapshotName, guestPath)
	msg := fmt.Sprintf(
		"Content unavailable — this file was seen during the session but is not on the evidence snapshot disk.\n\n"+
			"Typical cause: a short-lived temp file (e.g. PowerShell __PSScriptPolicyTest_*) created during capture and deleted before the snapshot was taken.\n\n"+
			"Path: %s",
		guestPath,
	)
	if meta != nil {
		if meta.Time != "" {
			msg += fmt.Sprintf("\nSysmon FileCreate: %s", meta.Time)
		}
		if meta.Image != "" {
			msg += fmt.Sprintf("\nProcess: %s", meta.Image)
		}
	}
	out := map[string]any{
		"path":        guestPath,
		"content":     msg,
		"unavailable": true,
		"reason":      reason,
	}
	if meta != nil {
		out["sysmon"] = meta
	}
	return out
}

// ListDirectory lists directory on snapshot disk.
func (a *App) ListDirectory(snapshotName, guestPath string) (any, error) {
	if a.Disk == nil {
		return nil, fmt.Errorf("disk reader unavailable")
	}
	return a.Disk.ListDirectory(snapshotName, guestPath)
}

// RegistryTreeFromDiff builds registry tree from diff registry section.
func (a *App) RegistryTreeFromDiff(diffJSON string) (any, error) {
	var d diff.Result
	if err := json.Unmarshal([]byte(diffJSON), &d); err != nil {
		return nil, err
	}
	var entries []registry.ChangedEntry
	for _, e := range d.Registry.Added {
		entries = append(entries, registry.ChangedEntry{
			Key: e.K, Name: e.N, Type: e.T, Value: e.V, Change: "added",
		})
	}
	for _, e := range d.Registry.Removed {
		entries = append(entries, registry.ChangedEntry{
			Key: e.K, Name: e.N, Type: e.T, Value: e.V, Change: "removed",
		})
	}
	for _, m := range d.Registry.Modified {
		entries = append(entries, registry.ChangedEntry{
			Key: m.Key, Name: m.Name, Change: "modified",
			Before: m.Before, After: m.After,
			BeforeType: m.BeforeType, AfterType: m.AfterType,
			Value: m.After, Type: m.AfterType,
		})
	}
	flat := make([]evidence.RegistryEntry, 0, len(entries))
	for _, e := range entries {
		flat = append(flat, evidence.RegistryEntry{K: e.Key, N: e.Name, T: e.Type, V: e.Value})
	}
	sidNames := a.registrySIDNames(d.Meta.FromSnapshot, d.Meta.ToSnapshot, flat)
	return registry.BuildChangedTree(entries, sidNames), nil
}

// registrySIDNames resolves HKU SIDs to account names from payload sidecars / config.
func (a *App) registrySIDNames(fromSnap, toSnap string, entries []evidence.RegistryEntry) map[string]string {
	out := map[string]string{}
	load := func(snap string) {
		if snap == "" || a.Evidence == nil {
			return
		}
		sc, err := a.Evidence.LoadSidecar(snap, "-payload-registry.json")
		if err != nil {
			return
		}
		sid, _ := sc["sid"].(string)
		user, _ := sc["userName"].(string)
		if sid != "" && user != "" {
			out[sid] = user
		}
	}
	load(fromSnap)
	load(toSnap)

	payloadUser := ""
	guestUser := ""
	if a.Cfg != nil {
		payloadUser = strings.TrimSpace(a.Cfg.Payload.Username)
		guestUser = strings.TrimSpace(a.Cfg.Guest.Username)
	}
	for _, sid := range registry.CollectSIDsFromEntries(entries) {
		if _, ok := out[sid]; ok {
			continue
		}
		upper := strings.ToUpper(sid)
		switch {
		case strings.HasSuffix(upper, "-500"):
			out[sid] = "Administrator"
		case strings.HasSuffix(upper, "-501"):
			out[sid] = "Guest"
		case guestUser != "" && strings.HasSuffix(upper, "-1002"):
			out[sid] = guestUser
		case payloadUser != "" && strings.HasPrefix(upper, "S-1-5-21-"):
			out[sid] = payloadUser
		}
	}
	return out
}

// FileTreeFromDiff builds file path tree nodes from diff files section.
func (a *App) FileTreeFromDiff(diffJSON string) (any, error) {
	var d diff.Result
	if err := json.Unmarshal([]byte(diffJSON), &d); err != nil {
		return nil, err
	}
	root := map[string]any{"name": "C:\\", "path": "C:\\", "children": map[string]any{}}
	addPath := func(path string, meta map[string]any) {
		if diff.ShouldHideUSNLeafFile(diff.FileDetail{Path: path}) {
			return
		}
		parts := splitPath(path)
		node := root
		acc := ""
		for i, part := range parts {
			if acc == "" {
				acc = part
			} else {
				acc = acc + `\` + part
			}
			children, _ := node["children"].(map[string]any)
			if children == nil {
				children = map[string]any{}
				node["children"] = children
			}
			child, ok := children[part].(map[string]any)
			if !ok {
				child = map[string]any{"name": part, "path": acc, "children": map[string]any{}}
				children[part] = child
			}
			if i == len(parts)-1 {
				for k, v := range meta {
					child[k] = v
				}
			}
			node = child
		}
	}
	for _, f := range d.Files.Added {
		if diff.ShouldHideUSNLeafFile(f) {
			continue
		}
		meta := map[string]any{"change": "added"}
		if diff.IsEphemeralTempPath(f.Path) {
			meta["previewUnavailable"] = true
		}
		addPath(f.Path, meta)
	}
	for _, f := range d.Files.Removed {
		if diff.ShouldHideUSNLeafFile(f) {
			continue
		}
		addPath(f.Path, map[string]any{"change": "removed"})
	}
	for _, f := range d.Files.Modified {
		if diff.ShouldHideUSNLeafFile(f.After) || diff.ShouldHideUSNLeafFile(f.Before) {
			continue
		}
		addPath(f.Path, map[string]any{"change": "modified"})
	}
	return root, nil
}

func splitPath(p string) []string {
	p = filepath.Clean(p)
	p = filepath.ToSlash(p)
	parts := []string{}
	for _, part := range splitDrive(p) {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return parts
}

func splitDrive(p string) []string {
	if len(p) >= 2 && p[1] == ':' {
		return append([]string{p[:2]}, splitSlash(p[2:])...)
	}
	return splitSlash(p)
}

func splitSlash(p string) []string {
	p = trimSlash(p)
	if p == "" {
		return nil
	}
	out := []string{}
	cur := ""
	for _, ch := range p {
		if ch == '/' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(ch)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func trimSlash(p string) string {
	for len(p) > 0 && (p[0] == '/' || p[0] == '\\') {
		p = p[1:]
	}
	return p
}

// --- Wails bindings ---

// GetConfigSummary returns VM config for UI.
func (a *App) GetConfigSummary() map[string]string {
	return map[string]string{
		"vmName":         a.Cfg.VMName,
		"manifestLogDir": a.Cfg.ManifestLogDir(),
		"baseline":       a.Cfg.Manifest.SessionBaselineSnapshot,
	}
}

// LoadDiffFile reads a diff JSON file from disk.
func (a *App) LoadDiffFile(path string) (string, error) {
	if path == "" {
		path = a.LastDiffPath
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// CompareSnapshotsJSON runs diff and returns JSON string for UI.
func (a *App) CompareSnapshotsJSON(fromSnap, toSnap string, refresh bool) (string, error) {
	a.logInfo(fmt.Sprintf("Compare %s → %s (refresh=%v)", fromSnap, toSnap, refresh))
	result, path, err := a.CompareSnapshots(a.WailsCtx, fromSnap, toSnap, refresh)
	if err != nil {
		a.logError(err.Error())
		return "", err
	}
	a.LastDiffPath = path
	raw, err := json.Marshal(result)
	if err != nil {
		a.logError(err.Error())
		return "", err
	}
	a.logInfo("Diff saved: " + path)
	return string(raw), nil
}

// GetVMStatusWails exposes VM status to frontend.
func (a *App) GetVMStatusWails() (map[string]string, error) {
	ctx := a.WailsCtx
	if ctx == nil {
		ctx = context.Background()
	}
	st, err := a.VMStatus(ctx)
	if err != nil {
		return nil, err
	}
	m, ok := st.(map[string]string)
	if !ok {
		m = map[string]string{}
	}
	if a.Cfg.Agent.Enabled {
		m["agentEnabled"] = "true"
		// Short timeout — never block the UI on a hung NAT/agent socket.
		healthCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if health, err := a.Evidence.AgentHealthQuick(healthCtx); err == nil {
			m["agentVersion"] = health.Version
			m["agentPayloadSession"] = fmt.Sprintf("%v", health.PayloadSession)
			m["agentSysmon"] = fmt.Sprintf("%v", health.SysmonAvailable)
			m["agentUSN"] = fmt.Sprintf("%v", health.USNAvailable)
			m["agentCaptureReady"] = fmt.Sprintf("%v", health.CaptureReady)
			m["agentStatus"] = "ok"
		} else {
			m["agentStatus"] = "unreachable"
			m["agentError"] = err.Error()
			if hint := a.agentNatHint(); hint != "" {
				m["agentError"] = err.Error() + " — " + hint
			}
		}
	}
	m["networkMode"] = a.Cfg.Network.Mode
	if a.Cfg.IsGatewayMode() {
		m["gateway"] = "on"
	}
	return m, nil
}

// agentReachHint explains how the host reaches the guest agent (gateway-only).
func (a *App) agentNatHint() string {
	if a.VM == nil || !a.Cfg.IsGatewayMode() {
		return ""
	}
	return "host reaches the agent via the Linux gateway only (127.0.0.1:9443 → gateway NAT → lab LAN)"
}

// InstallAgentWails deploys agent files to the guest and prints elevated install steps.
func (a *App) InstallAgentWails() (string, error) {
	ctx := a.WailsCtx
	if ctx == nil {
		ctx = context.Background()
	}
	state, _ := a.VM.VBox.VMState(a.Cfg.VMName)
	if state != "running" && state != "paused" {
		return "", fmt.Errorf("VM must be running to install agent (state: %s)", state)
	}
	a.logInfo("Ensuring NAT port forward for quarantine-agent…")
	if err := a.Network.EnsureAgentPortForward(); err != nil {
		a.logError(err.Error())
		return "", err
	}
	if err := a.Evidence.EnsureHostAgentToken(); err != nil {
		a.logInfo("Syncing agent token from guest…")
		if syncErr := a.Evidence.SyncAgentTokenFromGuest(); syncErr != nil {
			a.logInfo(syncErr.Error())
		}
	}
	a.logInfo(fmt.Sprintf("Deploying quarantine-agent v%s to guest…", agenttypes.Version))
	if _, err := a.Evidence.DeployAgent(""); err != nil {
		a.logError(err.Error())
		return "", err
	}
	msg := fmt.Sprintf(`Deployed quarantine-agent v%s to guest.

Run in elevated guest PowerShell:
  %s

Then on the host:
  .\quarantine-vm.ps1 agent sync-token
  .\quarantine-vm.ps1 agent health
`, agenttypes.Version, evidence.AgentInstallInstructions())
	a.logInfo(msg)
	if health, err := a.Evidence.AgentHealth(ctx); err == nil {
		msg += fmt.Sprintf("\n(Current agent v%s reachable — re-run guest script to upgrade service.)", health.Version)
	}
	return msg, nil
}

// SyncAgentTokenWails copies the guest agent token to the host secrets file.
func (a *App) SyncAgentTokenWails() (string, error) {
	if err := a.Evidence.SyncAgentTokenFromGuest(); err != nil {
		a.logError(err.Error())
		return "", err
	}
	a.logInfo("Agent token synced to " + a.Cfg.Agent.TokenFile)
	return "Token synced", nil
}

// AgentHealthWails returns agent /health JSON for the UI/CLI.
func (a *App) AgentHealthWails() (map[string]any, error) {
	healthCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	h, err := a.Evidence.AgentHealthQuick(healthCtx)
	if err != nil {
		if hint := a.agentNatHint(); hint != "" {
			return nil, fmt.Errorf("%w — %s", err, hint)
		}
		return nil, err
	}
	raw, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ReadSnapshotFileWails reads guest file for preview panel.
func (a *App) ReadSnapshotFileWails(snapshotName, guestPath string) (map[string]any, error) {
	return a.ReadSnapshotFile(snapshotName, guestPath)
}

// BuildRegistryTreeWails builds registry tree from diff JSON string.
func (a *App) BuildRegistryTreeWails(diffJSON string) (any, error) {
	return a.RegistryTreeFromDiff(diffJSON)
}

// BuildFileTreeWails builds file tree from diff JSON string.
func (a *App) BuildFileTreeWails(diffJSON string) (any, error) {
	return a.FileTreeFromDiff(diffJSON)
}

// ListSnapshotsWails lists snapshots for picker.
func (a *App) ListSnapshotsWails() ([]map[string]string, error) {
	ctx := a.WailsCtx
	if ctx == nil {
		ctx = context.Background()
	}
	list, err := a.VM.ListSnapshots(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]string, 0, len(list))
	for _, s := range list {
		out = append(out, map[string]string{
			"name": s.Name,
			"uuid": s.UUID,
		})
	}
	return out, nil
}

func (a *App) ensureManifestPublished(snap string) error {
	path, err := a.Evidence.PublishFromSidecars(snap)
	if err == nil {
		if path != "" {
			a.logInfo("Manifest: " + path)
			if _, pErr := a.Evidence.LoadSidecar(snap, "-payload-registry.json"); pErr != nil {
				a.logInfo(fmt.Sprintf("Note: %q has no payload registry sidecar — registry diff will be empty", snap))
			}
		}
		return nil
	}
	if !strings.Contains(err.Error(), "sidecar missing") {
		return err
	}
	state, _ := a.VM.VBox.VMState(a.Cfg.VMName)
	if state != "running" && state != "paused" {
		return fmt.Errorf("%w — start the VM and compare with Refresh to capture live sidecars", err)
	}
	a.logInfo(fmt.Sprintf("Sidecars missing for %q — capturing live…", snap))
	if _, capErr := a.Evidence.MarkLiveSnapshot(snap); capErr != nil {
		return fmt.Errorf("live capture for %q: %w", snap, capErr)
	}
	path, pubErr := a.Evidence.PublishFromSidecars(snap)
	if pubErr != nil {
		return pubErr
	}
	if path != "" {
		a.logInfo("Manifest: " + path)
	}
	return nil
}

func (a *App) captureLiveManifest(snapshotName string, afterSnapshot bool) error {
	state, err := a.VM.VBox.VMState(a.Cfg.VMName)
	if err != nil {
		return err
	}
	if state != "running" && state != "paused" {
		a.logInfo(fmt.Sprintf("Skipping live capture for %q (VM %s)", snapshotName, state))
		return nil
	}
	if a.Cfg.Agent.Enabled {
		_ = a.Network.EnsureAgentPortForward()
		_ = a.Evidence.EnsureHostAgentToken()
		if afterSnapshot {
			// VBox snapshot can briefly lock the guest system volume.
			time.Sleep(3 * time.Second)
		}
		a.logInfo(fmt.Sprintf("Capturing via quarantine-agent for %q…", snapshotName))
	} else {
		a.logInfo(fmt.Sprintf("Capturing live manifest sidecars for %q…", snapshotName))
	}
	path, err := a.Evidence.MarkLiveSnapshot(snapshotName)
	if err != nil {
		a.logError(err.Error())
		return err
	}
	if path != "" {
		a.logInfo("Manifest sidecars saved: " + path)
	}
	if a.Evidence.HasRegistryHives(snapshotName) {
		a.logInfo("Building registry index from live hive dump for " + snapshotName + "…")
		if meta, err := a.ensureHiveIndex(snapshotName, true); err != nil {
			a.logInfo("Registry index from hive dump failed: " + err.Error())
		} else if meta != nil {
			a.logInfo(fmt.Sprintf("Registry index ready (%d entries, no disk flatten)", meta.EntryCount))
		}
	}
	return nil
}

// TakeSnapshotWails creates a named snapshot (force replace if exists).
func (a *App) TakeSnapshotWails(name, description string, force bool) error {
	ctx := a.WailsCtx
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("snapshot name required")
	}
	a.logInfo(fmt.Sprintf("Take snapshot %q (force=%v) — capturing baseline then freezing VM", name, force))
	if capErr := a.captureLiveManifest(name, false); capErr != nil {
		a.logError(capErr.Error())
		return capErr
	}
	err := a.VM.SaveSnapshot(ctx, name, description, false, force)
	if err != nil {
		a.logError(err.Error())
		return fmt.Errorf("sidecars saved but snapshot failed: %w", err)
	}
	a.logInfo("Snapshot saved: " + name)
	return nil
}

// stopCaptureIfRunning finalizes PCAP/proxy logs when a capture session is active.
// Errors are logged but not returned — preserve/launch should not fail on capture.
func (a *App) stopCaptureIfRunning(reason string) {
	a.stopCaptureAndAttach("", reason)
}

// stopCaptureAndAttach stops capture; when snapshotName is set, moves PCAP/proxy into {snap}-network/.
func (a *App) stopCaptureAndAttach(snapshotName, reason string) {
	if a.Capture == nil || !a.Cfg.Network.Capture.Enabled {
		return
	}
	info := a.Capture.Info()
	if !info.Running {
		return
	}
	a.logInfo(fmt.Sprintf("Stopping packet capture (%s)…", reason))
	pull, err := a.Capture.StopWithResult()
	if err != nil {
		a.logInfo("Packet capture stop warning: " + err.Error())
		return
	}
	a.logInfo("Packet capture stopped")
	if snapshotName == "" || a.Evidence == nil {
		return
	}
	if pull.PcapPath == "" && pull.ProxyDir == "" {
		return
	}
	dest, err := a.Evidence.AttachNetworkArtifacts(snapshotName, pull.PcapPath, pull.ProxyDir)
	if err != nil {
		a.logInfo("Attach network artifacts warning: " + err.Error())
		return
	}
	if dest != "" {
		a.logInfo("Network evidence attached: " + dest)
	}
}

// startCaptureAfterLaunch starts capture when enabled (best-effort; does not fail launch).
func (a *App) startCaptureAfterLaunch() {
	if a.Capture == nil || !a.Cfg.Network.Capture.Enabled {
		return
	}
	a.logInfo("Starting packet capture…")
	path, err := a.Capture.Start()
	if err != nil {
		a.logInfo("Packet capture not started: " + err.Error())
		return
	}
	a.logInfo("Packet capture started: " + path)
}

// PreserveEvidenceWails captures sidecars then saves an Evidence-* snapshot.
func (a *App) PreserveEvidenceWails(label string) (string, error) {
	ctx := a.WailsCtx
	if ctx == nil {
		ctx = context.Background()
	}
	name := strings.TrimSpace(label)
	if name == "" {
		name = time.Now().Format("20060102-150405")
	}
	if !strings.HasPrefix(strings.ToLower(name), "evidence-") {
		name = "Evidence-" + name
	}
	a.logInfo(fmt.Sprintf("Preserve evidence %q — capturing sidecars…", name))
	if capErr := a.captureLiveManifest(name, false); capErr != nil {
		return "", capErr
	}
	a.stopCaptureAndAttach(name, "preserve")
	a.logInfo(fmt.Sprintf("Taking snapshot %q…", name))
	if err := a.VM.SaveSnapshot(ctx, name, "Evidence preserve", false, true); err != nil {
		a.logError(err.Error())
		return name, fmt.Errorf("sidecars saved but snapshot failed: %w", err)
	}
	a.logInfo("Evidence snapshot: " + name)
	if a.Evidence != nil && a.Evidence.HasRegistryHives(name) {
		a.logInfo("Building registry index from live hive dump for " + name + "…")
		if meta, err := a.ensureHiveIndex(name, true); err != nil {
			a.logInfo("Registry index build deferred: " + err.Error())
		} else if meta != nil {
			a.logInfo(fmt.Sprintf("Registry index ready (%d entries)", meta.EntryCount))
		}
	} else if a.Evidence != nil && !a.Evidence.HasRegistryIndex(name) {
		a.logInfo("No live hive dump for " + name + " — install agent 1.0.13+ or enable registryDiskFlatten for offline RAW extract")
	}
	return name, nil
}

// ResetToSnapshotWails restores a snapshot by name.
func (a *App) ResetToSnapshotWails(name string, clean bool) error {
	ctx := a.WailsCtx
	if ctx == nil {
		ctx = context.Background()
	}
	return a.VM.Reset(ctx, name, clean)
}

// LaunchSnapshotWails restores a snapshot and starts the VM GUI.
func (a *App) LaunchSnapshotWails(name string, clean bool) (string, error) {
	ctx := a.WailsCtx
	if ctx == nil {
		ctx = context.Background()
	}
	name = strings.TrimSpace(name)
	if !clean && name == "" {
		return "", fmt.Errorf("snapshot name required")
	}
	a.logInfo(fmt.Sprintf("Launch snapshot %q (clean=%v)", name, clean))
	if err := a.VM.Launch(ctx, name, clean); err != nil {
		a.logError(err.Error())
		return "", err
	}
	a.startCaptureAfterLaunch()
	launched := name
	if clean {
		launched = a.Cfg.CleanSnapshot
	}
	st, _ := a.VM.VBox.VMState(a.Cfg.VMName)
	if st == "" {
		st = "unknown"
	}
	msg := fmt.Sprintf("Launched %s (%s)", launched, st)
	a.logInfo(msg)
	return msg, nil
}

// DeleteSnapshotWails deletes a snapshot (and branch when force), cleaning manifest artifacts.
func (a *App) DeleteSnapshotWails(name string, force bool) (string, error) {
	ctx := a.WailsCtx
	if ctx == nil {
		ctx = context.Background()
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("snapshot name required")
	}

	a.logInfo(fmt.Sprintf("Delete snapshot %q (force=%v)", name, force))

	tree, err := a.VM.VBox.ListSnapshotTree(a.Cfg.VMName)
	if err != nil {
		return "", err
	}
	var target *vbox.SnapshotTreeEntry
	for i := range tree {
		if strings.EqualFold(tree[i].Name, name) {
			target = &tree[i]
			break
		}
	}
	if target == nil {
		return "", fmt.Errorf("snapshot not found: %s", name)
	}

	namesToClean := []string{target.Name}
	for _, u := range vbox.DescendantUUIDs(target.UUID, tree) {
		for _, e := range tree {
			if e.UUID == u {
				namesToClean = append(namesToClean, e.Name)
				break
			}
		}
	}

	if err := a.VM.DeleteSnapshot(ctx, name, force); err != nil {
		a.logError(err.Error())
		return "", err
	}

	var deleted []string
	for _, snapName := range namesToClean {
		a.Evidence.RemoveSnapshotArtifacts(snapName)
		deleted = append(deleted, snapName)
	}
	msg := fmt.Sprintf("Deleted: %s", strings.Join(deleted, ", "))
	a.logInfo(msg)
	return msg, nil
}

// CaptureStatusWails returns packet-capture status for the UI.
func (a *App) CaptureStatusWails() (map[string]any, error) {
	if a.Capture == nil {
		return map[string]any{"running": false, "message": "capture unavailable", "enabled": false}, nil
	}
	info := a.Capture.Info()
	return map[string]any{
		"running":   info.Running,
		"mode":      info.Mode,
		"pcapPath":  info.PcapPath,
		"startedAt": info.StartedAt,
		"message":   info.Message,
		"stale":     info.Stale,
		"enabled":   info.Enabled,
	}, nil
}

// StartCaptureWails starts guest-nic packet capture.
func (a *App) StartCaptureWails() (map[string]any, error) {
	if a.Capture == nil {
		return nil, fmt.Errorf("capture unavailable")
	}
	a.logInfo("Starting packet capture…")
	path, err := a.Capture.Start()
	if err != nil {
		a.logError(err.Error())
		return nil, err
	}
	a.logInfo("Packet capture started: " + path)
	info := a.Capture.Info()
	return map[string]any{
		"running":   info.Running,
		"mode":      info.Mode,
		"pcapPath":  info.PcapPath,
		"startedAt": info.StartedAt,
		"message":   info.Message,
		"enabled":   info.Enabled,
	}, nil
}

// StopCaptureWails stops packet capture.
func (a *App) StopCaptureWails() (map[string]any, error) {
	if a.Capture == nil {
		return nil, fmt.Errorf("capture unavailable")
	}
	a.logInfo("Stopping packet capture…")
	if err := a.Capture.Stop(); err != nil {
		a.logError(err.Error())
		return nil, err
	}
	a.logInfo("Packet capture stopped")
	info := a.Capture.Info()
	return map[string]any{
		"running":   info.Running,
		"mode":      info.Mode,
		"pcapPath":  info.PcapPath,
		"startedAt": info.StartedAt,
		"message":   info.Message,
		"enabled":   info.Enabled,
	}, nil
}

// GatewayStatusWails returns Linux gateway VM status for the UI sidebar.
// Uses VirtualBox state only — never guestcontrol (that can block the VBox lock for minutes).
func (a *App) GatewayStatusWails() (map[string]any, error) {
	mode := a.Cfg.Network.Mode
	g := a.Cfg.Network.Gateway.WithDefaults(a.Cfg.Network.IntnetName)
	out := map[string]any{
		"enabled":    a.Cfg.IsGatewayMode() || g.Enabled,
		"mode":       mode,
		"vmName":     g.VMName,
		"lanGateway": g.LANGateway,
		"guestIp":    g.GuestIP,
		"intnetName": g.IntnetName,
		"status":     "unavailable",
	}
	state, err := a.VM.VBox.VMState(g.VMName)
	if err != nil {
		out["vmState"] = "missing"
		out["status"] = fmt.Sprintf("%s missing", g.VMName)
		return out, nil
	}
	out["vmState"] = state
	out["status"] = fmt.Sprintf("%s state=%s lan=%s", g.VMName, state, g.LANGateway)
	return out, nil
}
