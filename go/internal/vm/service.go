package vm

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/network"
	"github.com/quarantine-lab/quarantine/internal/vbox"
)

// Service provides VM lifecycle operations.
type Service struct {
	Cfg    *config.Config
	VBox   *vbox.Client
	ConfigPath string
}

// NewService creates a VM service.
func NewService(cfgPath string) (*Service, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}
	vb, err := vbox.NewClient(cfg.VBoxManagePath)
	if err != nil {
		return nil, err
	}
	return &Service{Cfg: cfg, VBox: vb, ConfigPath: cfgPath}, nil
}

// Status returns VM status summary.
func (s *Service) Status(ctx context.Context) (map[string]string, error) {
	state, err := s.VBox.VMState(s.Cfg.VMName)
	if err != nil {
		if strings.Contains(err.Error(), "could not find") {
			state = "notfound"
		} else {
			return nil, err
		}
	}
	return map[string]string{
		"vmName":        s.Cfg.VMName,
		"state":         state,
		"networkMode":   s.Cfg.Network.Mode,
		"cleanSnapshot": s.Cfg.CleanSnapshot,
		"vmDataDir":     s.Cfg.DataDir(),
		"vmFolder":      s.Cfg.VMFolder(),
		"diskPath":      s.Cfg.DiskPathResolved(),
	}, nil
}

// ListSnapshots lists VM snapshots.
func (s *Service) ListSnapshots(ctx context.Context) ([]vbox.SnapshotInfo, error) {
	return s.VBox.ListSnapshots(s.Cfg.VMName)
}

// SaveSnapshot takes a snapshot, optionally replacing existing same name.
func (s *Service) SaveSnapshot(ctx context.Context, name, description string, offline, force bool) error {
	if strings.TrimSpace(name) == "" {
		name = s.Cfg.CleanSnapshot
	}
	if description == "" {
		description = "Quarantine snapshot"
	}
	state, _ := s.VBox.VMState(s.Cfg.VMName)
	if offline && (state == "running" || state == "paused" || state == "starting") {
		_ = s.VBox.PowerOff(s.Cfg.VMName)
		time.Sleep(3 * time.Second)
		state, _ = s.VBox.VMState(s.Cfg.VMName)
	}
	if offline && state == "saved" {
		_ = s.VBox.DiscardState(s.Cfg.VMName)
		time.Sleep(time.Second)
	}
	snaps, _ := s.VBox.ListSnapshots(s.Cfg.VMName)
	for _, snap := range snaps {
		if strings.EqualFold(snap.Name, name) {
			if !force {
				return fmt.Errorf("snapshot %q already exists (use -force)", name)
			}
			if err := s.VBox.DeleteSnapshot(s.Cfg.VMName, snap.UUID); err != nil {
				return fmt.Errorf("delete existing snapshot: %w", err)
			}
		}
	}
	if err := s.VBox.TakeSnapshot(s.Cfg.VMName, name, description); err != nil {
		return err
	}
	return nil
}

// Preserve saves an Evidence-* snapshot.
func (s *Service) Preserve(ctx context.Context, label string) (string, error) {
	name := label
	if name == "" {
		name = time.Now().Format("20060102-150405")
	}
	if !strings.HasPrefix(strings.ToLower(name), "evidence-") {
		name = "Evidence-" + name
	}
	if err := s.SaveSnapshot(ctx, name, "Evidence preserve", false, true); err != nil {
		return "", err
	}
	return name, nil
}

// Reset restores a snapshot by name or clean snapshot.
func (s *Service) Reset(ctx context.Context, snapshotName string, clean bool) error {
	name := snapshotName
	if clean || name == "" {
		name = s.Cfg.CleanSnapshot
	}
	uuid, err := s.VBox.SnapshotUUID(s.Cfg.VMName, name)
	if err != nil {
		return err
	}
	state, _ := s.VBox.VMState(s.Cfg.VMName)
	if state == "running" || state == "paused" {
		_ = s.VBox.PowerOff(s.Cfg.VMName)
		time.Sleep(3 * time.Second)
	}
	return s.VBox.RestoreSnapshot(s.Cfg.VMName, uuid)
}

// Launch restores a snapshot and starts the VM (live snapshots resume logged-in session).
func (s *Service) Launch(ctx context.Context, snapshotName string, clean bool) error {
	if err := s.Reset(ctx, snapshotName, clean); err != nil {
		return err
	}
	state, err := s.VBox.VMState(s.Cfg.VMName)
	if err != nil {
		return err
	}
	switch state {
	case "running", "paused", "starting":
		return nil
	default:
		return s.VBox.StartVM(s.Cfg.VMName)
	}
}

// DeleteSnapshot removes a snapshot by name, optionally its branch, with baseline protection.
func (s *Service) DeleteSnapshot(ctx context.Context, name string, force bool) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("snapshot name required")
	}

	protected := map[string]bool{
		strings.ToLower(s.Cfg.CleanSnapshot): true,
		strings.ToLower(s.Cfg.Manifest.SessionBaselineSnapshot): true,
	}
	if protected[strings.ToLower(name)] && !force {
		return fmt.Errorf("refusing to delete protected baseline %q (enable Force)", name)
	}

	tree, err := s.VBox.ListSnapshotTree(s.Cfg.VMName)
	if err != nil {
		return err
	}
	var target *vbox.SnapshotTreeEntry
	for i := range tree {
		if strings.EqualFold(tree[i].Name, name) {
			target = &tree[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("snapshot not found: %s", name)
	}

	descendants := vbox.DescendantUUIDs(target.UUID, tree)
	if len(descendants) > 0 && !force {
		var childNames []string
		descSet := map[string]bool{}
		for _, u := range descendants {
			descSet[u] = true
		}
		for _, e := range tree {
			if descSet[e.UUID] {
				childNames = append(childNames, e.Name)
			}
		}
		return fmt.Errorf("snapshot %q has child snapshots (%s); enable Force to delete the whole branch",
			name, strings.Join(childNames, ", "))
	}

	deleteSet := map[string]vbox.SnapshotTreeEntry{target.UUID: *target}
	for _, u := range descendants {
		for _, e := range tree {
			if e.UUID == u {
				deleteSet[u] = e
				break
			}
		}
	}

	toDelete := make([]vbox.SnapshotTreeEntry, 0, len(deleteSet))
	for _, e := range deleteSet {
		toDelete = append(toDelete, e)
	}
	sort.Slice(toDelete, func(i, j int) bool {
		return len(toDelete[i].Suffix) > len(toDelete[j].Suffix)
	})

	for _, e := range toDelete {
		if err := s.VBox.DeleteSnapshot(s.Cfg.VMName, e.UUID); err != nil {
			return fmt.Errorf("delete %q: %w", e.Name, err)
		}
	}
	return nil
}

// Start starts the VM GUI.
func (s *Service) Start(ctx context.Context) error {
	if err := s.VBox.StartVM(s.Cfg.VMName); err != nil {
		return err
	}
	// Best-effort agent port-forward (lab NAT, or Linux gateway DNAT in gateway mode).
	if s.Cfg.Agent.Enabled {
		mode := strings.ToLower(strings.TrimSpace(s.Cfg.Network.Mode))
		if mode == "quarantine" || mode == "nat" || mode == "gateway" || mode == "" {
			_ = network.New(s.Cfg, s.VBox).EnsureAgentPortForward()
		}
	}
	return nil
}

// Stop powers off the VM.
func (s *Service) Stop(ctx context.Context) error {
	return s.VBox.PowerOff(s.Cfg.VMName)
}

// Baseline clears snapshots and saves disk-only Clean.
func (s *Service) Baseline(ctx context.Context) error {
	snaps, err := s.VBox.ListSnapshots(s.Cfg.VMName)
	if err != nil {
		return err
	}
	for i := len(snaps) - 1; i >= 0; i-- {
		_ = s.VBox.DeleteSnapshot(s.Cfg.VMName, snaps[i].UUID)
	}
	state, _ := s.VBox.VMState(s.Cfg.VMName)
	if state == "running" || state == "paused" {
		_ = s.VBox.PowerOff(s.Cfg.VMName)
		time.Sleep(3 * time.Second)
	}
	if state == "saved" {
		_ = s.VBox.DiscardState(s.Cfg.VMName)
	}
	return s.SaveSnapshot(ctx, s.Cfg.CleanSnapshot, "Baseline disk-only Clean", true, true)
}
