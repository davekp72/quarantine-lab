package vbox

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Client wraps VBoxManage execution.
type Client struct {
	Binary string
	OnLog  func(level, message string)
}

// NewClient resolves VBoxManage path from config or common install locations.
func NewClient(configuredPath string) (*Client, error) {
	if configuredPath != "" {
		if _, err := os.Stat(configuredPath); err == nil {
			return &Client{Binary: configuredPath}, nil
		}
	}
	candidates := []string{
		filepath.Join(os.Getenv("ProgramFiles"), "Oracle", "VirtualBox", "VBoxManage.exe"),
		`D:\Program Files\Oracle\VirtualBox\VBoxManage.exe`,
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return &Client{Binary: c}, nil
		}
	}
	if p, err := exec.LookPath("VBoxManage"); err == nil {
		return &Client{Binary: p}, nil
	}
	return nil, fmt.Errorf("VBoxManage not found; set vboxManagePath in config")
}

// Run executes VBoxManage with arguments.
func (c *Client) Run(ctx context.Context, args ...string) (string, error) {
	if c.OnLog != nil {
		c.OnLog("cmd", "VBoxManage "+strings.Join(args, " "))
	}
	cmd := exec.CommandContext(ctx, c.Binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out := strings.TrimSpace(stdout.String())
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = out
		}
		if c.OnLog != nil {
			c.OnLog("error", msg)
		}
		return out, fmt.Errorf("VBoxManage %s: %w: %s", strings.Join(args, " "), err, msg)
	}
	if c.OnLog != nil && out != "" {
		c.OnLog("debug", out)
	}
	return out, nil
}

// RunWithTimeout runs with a default timeout.
func (c *Client) RunWithTimeout(timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return c.Run(ctx, args...)
}

// SnapshotInfo describes a VM snapshot from machine-readable list.
type SnapshotInfo struct {
	Name        string
	UUID        string
	Description string
}

// SnapshotTreeEntry is a snapshot node in VBox tree order.
type SnapshotTreeEntry struct {
	Suffix      string
	Name        string
	UUID        string
	Description string
}

var snapshotFieldRe = regexp.MustCompile(`^(SnapshotName|SnapshotUUID|SnapshotDescription)((?:-[0-9]+)*)="(.*)"$`)

func parseSnapshotTree(out string) []SnapshotTreeEntry {
	type entry map[string]string
	entries := map[string]entry{}
	var order []string

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		m := snapshotFieldRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		field, suffix, value := m[1], m[2], m[3]
		if _, ok := entries[suffix]; !ok {
			entries[suffix] = entry{}
			order = append(order, suffix)
		}
		entries[suffix][field] = value
	}

	var tree []SnapshotTreeEntry
	for _, suffix := range order {
		e := entries[suffix]
		name := e["SnapshotName"]
		uuid := e["SnapshotUUID"]
		if name == "" || uuid == "" {
			continue
		}
		tree = append(tree, SnapshotTreeEntry{
			Suffix:      suffix,
			Name:        name,
			UUID:        uuid,
			Description: e["SnapshotDescription"],
		})
	}
	return tree
}

// ListSnapshotTree returns the full snapshot tree in VBox order.
func (c *Client) ListSnapshotTree(vmName string) ([]SnapshotTreeEntry, error) {
	out, err := c.RunWithTimeout(2*time.Minute, "snapshot", vmName, "list", "--machinereadable")
	if err != nil {
		return nil, err
	}
	return parseSnapshotTree(out), nil
}

// DescendantUUIDs returns UUIDs of snapshots nested under targetUUID.
func DescendantUUIDs(targetUUID string, tree []SnapshotTreeEntry) []string {
	var target *SnapshotTreeEntry
	for i := range tree {
		if tree[i].UUID == targetUUID {
			target = &tree[i]
			break
		}
	}
	if target == nil {
		return nil
	}
	prefix := target.Suffix + "-"
	var uuids []string
	for _, e := range tree {
		if e.Suffix != target.Suffix && strings.HasPrefix(e.Suffix, prefix) {
			uuids = append(uuids, e.UUID)
		}
	}
	return uuids
}

// ListSnapshots returns snapshots for a VM (full tree, including nested children).
func (c *Client) ListSnapshots(vmName string) ([]SnapshotInfo, error) {
	tree, err := c.ListSnapshotTree(vmName)
	if err != nil {
		return nil, err
	}
	snaps := make([]SnapshotInfo, 0, len(tree))
	for _, e := range tree {
		snaps = append(snaps, SnapshotInfo{Name: e.Name, UUID: e.UUID, Description: e.Description})
	}
	return snaps, nil
}

// SnapshotUUID resolves snapshot name to UUID.
func (c *Client) SnapshotUUID(vmName, snapshotName string) (string, error) {
	snaps, err := c.ListSnapshots(vmName)
	if err != nil {
		return "", err
	}
	for _, s := range snaps {
		if strings.EqualFold(s.Name, snapshotName) {
			return s.UUID, nil
		}
	}
	return "", fmt.Errorf("snapshot not found: %s", snapshotName)
}

// VMState returns VMState from showvminfo --machinereadable.
func (c *Client) VMState(vmName string) (string, error) {
	out, err := c.RunWithTimeout(time.Minute, "showvminfo", vmName, "--machinereadable")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, `VMState="`) {
			val := strings.TrimPrefix(line, `VMState="`)
			val = strings.TrimSuffix(val, `"`)
			return strings.TrimSpace(val), nil
		}
	}
	return "", fmt.Errorf("VMState not found")
}

// TakeSnapshot creates a snapshot.
func (c *Client) TakeSnapshot(vmName, name, description string) error {
	args := []string{"snapshot", vmName, "take", name}
	if description != "" {
		args = append(args, "--description", description)
	}
	_, err := c.RunWithTimeout(30*time.Minute, args...)
	return err
}

// RestoreSnapshot restores by UUID.
func (c *Client) RestoreSnapshot(vmName, uuid string) error {
	_, err := c.RunWithTimeout(30*time.Minute, "snapshot", vmName, "restore", uuid)
	return err
}

// DeleteSnapshot deletes by UUID.
func (c *Client) DeleteSnapshot(vmName, uuid string) error {
	_, err := c.RunWithTimeout(30*time.Minute, "snapshot", vmName, "delete", uuid)
	return err
}

// StartVM starts or resumes the VM.
func (c *Client) StartVM(vmName string) error {
	_, err := c.RunWithTimeout(5*time.Minute, "startvm", vmName, "--type", "gui")
	return err
}

// PowerOff forces power off.
func (c *Client) PowerOff(vmName string) error {
	_, err := c.RunWithTimeout(2*time.Minute, "controlvm", vmName, "poweroff")
	return err
}

// DiscardState discards saved VM state.
func (c *Client) DiscardState(vmName string) error {
	_, err := c.RunWithTimeout(2*time.Minute, "discardstate", vmName)
	return err
}

// CloneMedium flattens a registered disk medium to a linear RAW image suitable for NTFS reads.
func (c *Client) CloneMedium(sourceMedium, outputPath string) error {
	source := formatMediumRef(sourceMedium)
	_, err := c.RunWithTimeout(2*time.Hour,
		"clonemedium", source, outputPath, "--format", "RAW")
	if err == nil {
		return nil
	}
	// Fallback: fixed VDI (linear payload; dynamic VDI uses a block map unreadable by go-ntfs).
	_, err = c.RunWithTimeout(2*time.Hour,
		"clonemedium", source, outputPath, "--format", "VDI", "--variant", "Fixed")
	if err == nil {
		return nil
	}
	// VirtualBox 6.x
	if strings.Contains(strings.ToLower(err.Error()), "unknown option") {
		_, err = c.RunWithTimeout(2*time.Hour,
			"clonehd", source, outputPath, "--format", "RAW")
	}
	return err
}

func formatMediumRef(medium string) string {
	medium = strings.TrimSpace(medium)
	if medium == "" {
		return medium
	}
	if strings.Contains(medium, `\`) || strings.Contains(medium, `/`) {
		return medium
	}
	clean := strings.Trim(medium, "{}")
	if len(clean) == 36 && strings.Count(clean, "-") == 4 {
		return "{" + clean + "}"
	}
	return medium
}

// CloneHDSnapshot is deprecated; kept for tests. Prefer CloneMedium with snapshot disk UUID.
func (c *Client) CloneHDSnapshot(baseVDI, snapshotUUID, outputVDI string) error {
	_, err := c.RunWithTimeout(2*time.Hour,
		"clonehd", baseVDI, outputVDI, "--format", "VDI", "--snapshot", snapshotUUID)
	return err
}

// ShowMediumInfo returns showmediuminfo output for a medium UUID or path.
func (c *Client) ShowMediumInfo(uuidOrPath string) (string, error) {
	return c.RunWithTimeout(2*time.Minute, "showmediuminfo", uuidOrPath)
}

// GuestControlRun runs a program in the guest.
func (c *Client) GuestControlRun(vmName, username, password, exe string, args []string, timeout time.Duration) (string, error) {
	guestArgs := []string{
		"guestcontrol", vmName, "run",
		"--username=" + username,
		"--password=" + password,
		"--exe", exe,
		"--timeout", fmt.Sprintf("%d", int(timeout.Milliseconds())),
		"--wait-stdout", "--wait-stderr",
		"--",
	}
	guestArgs = append(guestArgs, args...)
	return c.RunWithTimeout(timeout+30*time.Second, guestArgs...)
}

// GuestControlMkdir creates a directory in the guest (parents allowed).
func (c *Client) GuestControlMkdir(vmName, username, password, guestDir string, timeout time.Duration) error {
	_, err := c.RunWithTimeout(timeout+30*time.Second,
		"guestcontrol", vmName, "mkdir",
		"--username="+username,
		"--password="+password,
		"--parents",
		guestDir,
	)
	return err
}

// GuestControlCopyTo copies a host file into the guest.
// guestDest must be the full guest file path (VBox quirk: --target-directory takes the dest file).
func (c *Client) GuestControlCopyTo(vmName, username, password, hostPath, guestDest string, timeout time.Duration) error {
	dest := strings.ReplaceAll(guestDest, `/`, `\`)
	if strings.HasSuffix(dest, `\`) {
		dest = dest + filepath.Base(hostPath)
	}
	parent := dest
	if i := strings.LastIndex(dest, `\`); i > 0 {
		parent = dest[:i]
	}
	_ = c.GuestControlMkdir(vmName, username, password, parent, timeout)
	_, err := c.RunWithTimeout(timeout+30*time.Second,
		"guestcontrol", vmName, "copyto",
		"--username="+username,
		"--password="+password,
		"--target-directory="+dest,
		hostPath,
	)
	return err
}

// GuestControlCopyFrom copies a guest file to the host.
// hostPath must be the full host file path (same VBox --target-directory quirk).
func (c *Client) GuestControlCopyFrom(vmName, username, password, guestPath, hostPath string, timeout time.Duration) error {
	dest := hostPath
	if strings.HasSuffix(dest, `\`) || strings.HasSuffix(dest, `/`) {
		dest = filepath.Join(dest, filepath.Base(guestPath))
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	_, err := c.RunWithTimeout(timeout+30*time.Second,
		"guestcontrol", vmName, "copyfrom",
		"--username="+username,
		"--password="+password,
		"--target-directory="+dest,
		guestPath,
	)
	return err
}

// NatPFAdd adds a NAT port forwarding rule to NIC1.
// Uses controlvm when the VM is running (modifyvm requires the VM to be powered off).
func (c *Client) NatPFAdd(vmName, rule string) error {
	state, _ := c.VMState(vmName)
	if vmSessionActive(state) {
		_, err := c.RunWithTimeout(time.Minute, "controlvm", vmName, "natpf1", rule)
		return err
	}
	_, err := c.RunWithTimeout(time.Minute, "modifyvm", vmName, "--natpf1", rule)
	return err
}

// NatPFDelete removes a NAT port forwarding rule by name.
func (c *Client) NatPFDelete(vmName, ruleName string) error {
	state, _ := c.VMState(vmName)
	var err error
	if vmSessionActive(state) {
		_, err = c.RunWithTimeout(time.Minute, "controlvm", vmName, "natpf1", "delete", ruleName)
	} else {
		_, err = c.RunWithTimeout(time.Minute, "modifyvm", vmName, "--natpf1", "delete", ruleName)
	}
	return ignoreNatPFMissing(err)
}

func vmSessionActive(state string) bool {
	switch state {
	case "running", "paused", "starting", "stopping":
		return true
	default:
		return false
	}
}

func ignoreNatPFMissing(err error) error {
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "could not find") ||
		strings.Contains(msg, "natpf") && strings.Contains(msg, "not found") {
		return nil
	}
	return err
}

// ModifyVM sets a single modifyvm property.
func (c *Client) ModifyVM(vmName, key, value string) error {
	_, err := c.RunWithTimeout(2*time.Minute, "modifyvm", vmName, "--"+key, value)
	return err
}

// SharedFolderAdd adds a transient shared folder.
func (c *Client) SharedFolderAdd(vmName, name, hostPath string, readOnly bool) error {
	args := []string{"sharedfolder", "add", vmName, "--name=" + name, "--hostpath=" + hostPath, "--automount", "--transient"}
	if readOnly {
		args = append(args, "--readonly")
	}
	_, err := c.RunWithTimeout(time.Minute, args...)
	return err
}

// SharedFolderRemove removes a shared folder.
func (c *Client) SharedFolderRemove(vmName, name string) error {
	_, err := c.RunWithTimeout(time.Minute, "sharedfolder", "remove", vmName, "--name="+name)
	return err
}
