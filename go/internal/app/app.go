package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quarantine-lab/quarantine/internal/applog"
	agenttypes "github.com/quarantine-lab/quarantine/internal/agent/types"
	"github.com/quarantine-lab/quarantine/internal/capture"
	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/diff"
	"github.com/quarantine-lab/quarantine/internal/disk"
	"github.com/quarantine-lab/quarantine/internal/evidence"
	"github.com/quarantine-lab/quarantine/internal/inbox"
	"github.com/quarantine-lab/quarantine/internal/network"
	"github.com/quarantine-lab/quarantine/internal/proxy"
	"github.com/quarantine-lab/quarantine/internal/registry"
	"github.com/quarantine-lab/quarantine/internal/vm"
	"github.com/quarantine-lab/quarantine/internal/vbox"
)

// App is the central application facade for CLI and Wails.
type App struct {
	ConfigPath string
	Cfg        *config.Config
	VM         *vm.Service
	Evidence   *evidence.Service
	Network    *network.Service
	Proxy      *proxy.Manager
	Capture    *capture.Manager
	Inbox      *inbox.Service
	Disk       *disk.Reader
	WailsCtx   context.Context
	LastDiffPath string
	Log        *applog.Buffer
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
	a := &App{
		ConfigPath: configPath,
		Cfg:        cfg,
		VM:         vms,
		Evidence:   ev,
		Network:    network.New(cfg, vms.VBox),
		Proxy:      proxy.New(cfg, root),
		Capture:    capture.New(cfg),
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
	fromPath := a.Cfg.ManifestPath(from)
	toPath := a.Cfg.ManifestPath(to)
	result, err := diff.Compare(fromPath, toPath, left, right)
	if err != nil {
		return nil, "", err
	}
	diff.EnrichNetwork(a.ConfigPath, config.ProjectRoot(a.ConfigPath), result, left.CapturedAt, right.CapturedAt, result.Sysmon.Added)
	outPath := a.Evidence.DiffOutputPath(from, to)
	raw, _ := json.MarshalIndent(result, "", "  ")
	if err := os.WriteFile(outPath, raw, 0o644); err != nil {
		return nil, "", err
	}
	return result, outPath, nil
}

// ListSnapshots returns VBox snapshot list.
func (a *App) ListSnapshots(ctx context.Context) (any, error) {
	return a.VM.ListSnapshots(ctx)
}

// VMStatus returns VM status map.
func (a *App) VMStatus(ctx context.Context) (any, error) {
	return a.VM.Status(ctx)
}

// ReadSnapshotFile reads file content from snapshot disk.
func (a *App) ReadSnapshotFile(snapshotName, guestPath string) (map[string]any, error) {
	if a.Disk == nil {
		return nil, fmt.Errorf("disk reader unavailable")
	}
	data, info, err := a.Disk.ReadFile(snapshotName, guestPath, 512*1024)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"path":    info.Path,
		"size":    info.Size,
		"content": string(data),
		"base64":  false,
	}, nil
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
	var entries []evidence.RegistryEntry
	entries = append(entries, d.Registry.Added...)
	entries = append(entries, d.Registry.Removed...)
	for _, m := range d.Registry.Modified {
		entries = append(entries, evidence.RegistryEntry{K: m.Key, N: m.Name, V: m.After, T: m.AfterType})
	}
	return registry.BuildTree(entries), nil
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
		addPath(f.Path, map[string]any{"change": "added"})
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
		"vmName":        a.Cfg.VMName,
		"manifestLogDir": a.Cfg.ManifestLogDir(),
		"baseline":      a.Cfg.Manifest.SessionBaselineSnapshot,
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
		if health, err := a.Evidence.AgentHealth(ctx); err == nil {
			m["agentVersion"] = health.Version
			m["agentPayloadSession"] = fmt.Sprintf("%v", health.PayloadSession)
			m["agentSysmon"] = fmt.Sprintf("%v", health.SysmonAvailable)
			m["agentUSN"] = fmt.Sprintf("%v", health.USNAvailable)
			m["agentCaptureReady"] = fmt.Sprintf("%v", health.CaptureReady)
			m["agentStatus"] = "ok"
		} else {
			m["agentStatus"] = "unreachable"
			m["agentError"] = err.Error()
		}
	}
	return m, nil
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
  .\quarantine-go.ps1 agent sync-token
  .\quarantine-go.ps1 agent health
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

// AgentHealthWails returns agent /health JSON for the UI.
func (a *App) AgentHealthWails() (map[string]any, error) {
	ctx := a.WailsCtx
	if ctx == nil {
		ctx = context.Background()
	}
	h, err := a.Evidence.AgentHealth(ctx)
	if err != nil {
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
	a.logInfo(fmt.Sprintf("Take snapshot %q (force=%v)", name, force))
	err := a.VM.SaveSnapshot(ctx, name, description, false, force)
	if err != nil {
		a.logError(err.Error())
		return err
	}
	if capErr := a.captureLiveManifest(name, true); capErr != nil {
		return fmt.Errorf("snapshot saved but live capture failed: %w", capErr)
	}
	a.logInfo("Snapshot saved: " + name)
	return nil
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
	a.logInfo(fmt.Sprintf("Taking snapshot %q…", name))
	if err := a.VM.SaveSnapshot(ctx, name, "Evidence preserve", false, true); err != nil {
		a.logError(err.Error())
		return name, fmt.Errorf("sidecars saved but snapshot failed: %w", err)
	}
	a.logInfo("Evidence snapshot: " + name)
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
