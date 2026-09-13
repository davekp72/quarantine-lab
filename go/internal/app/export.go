package app

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/evidence"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// ExportPcapWails copies the evidence (or case) capture to a host path chosen in a save dialog.
func (a *App) ExportPcapWails(snapshotName string) (string, error) {
	src, err := a.evidencePcapPath(snapshotName)
	if err != nil {
		return "", err
	}
	base := filepath.Base(src)
	if snap := config.SafeSnapshotFileName(strings.TrimSpace(snapshotName)); snap != "" {
		ext := filepath.Ext(base)
		if ext == "" {
			ext = ".pcap"
		}
		base = snap + "-capture" + ext
	}
	dest, err := a.saveDialog("Save PCAP", base, []runtime.FileFilter{
		{DisplayName: "Packet capture", Pattern: "*.pcap;*.pcapng"},
	})
	if err != nil || dest == "" {
		return dest, err
	}
	if err := copyRegularFile(src, dest); err != nil {
		return "", err
	}
	a.logInfo("Exported PCAP to " + dest)
	return dest, nil
}

// ExportSnapshotFileWails writes the selected guest file to a host path chosen in a save dialog.
func (a *App) ExportSnapshotFileWails(snapshotName, guestPath string) (string, error) {
	data, src, err := a.loadExportFile(snapshotName, guestPath)
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", fmt.Errorf("no file bytes to export")
	}
	dest, err := a.saveDialog("Save file", exportBaseName(guestPath), nil)
	if err != nil || dest == "" {
		return dest, err
	}
	if err := os.WriteFile(dest, data, 0o644); err != nil {
		return "", err
	}
	a.logInfo(fmt.Sprintf("Exported %s (%s, %d bytes) to %s", guestPath, src, len(data), dest))
	return dest, nil
}

func (a *App) saveDialog(title, defaultName string, filters []runtime.FileFilter) (string, error) {
	if a == nil || a.WailsCtx == nil {
		return "", fmt.Errorf("save dialog unavailable")
	}
	opts := runtime.SaveDialogOptions{
		Title:           title,
		DefaultFilename: defaultName,
		Filters:         filters,
	}
	return runtime.SaveFileDialog(a.WailsCtx, opts)
}

func (a *App) loadExportFile(snapshotName, guestPath string) ([]byte, string, error) {
	guestPath = strings.TrimSpace(guestPath)
	if guestPath == "" {
		return nil, "", fmt.Errorf("file path required")
	}
	if a != nil && strings.TrimSpace(a.ActiveCase) != "" && a.Cases != nil {
		from, to, _, err := a.Cases.ReadBodies(a.ActiveCase, guestPath)
		if err != nil {
			return nil, "", err
		}
		if len(to) > 0 {
			return to, "case", nil
		}
		if len(from) > 0 {
			return from, "case", nil
		}
		return nil, "", fmt.Errorf("no archived body for %s", guestPath)
	}
	snapshotName = strings.TrimSpace(snapshotName)
	if snapshotName == "" {
		return nil, "", fmt.Errorf("snapshot name required")
	}
	if a.Evidence != nil {
		if data, ok := a.Evidence.FileContentFromSidecar(snapshotName, guestPath); ok && len(data) > 0 {
			return data, "sidecar", nil
		}
		if entry, ok := a.Evidence.FileSidecarEntry(snapshotName, guestPath); ok {
			if data, ok := evidence.FileSidecarBeforeContent(entry); ok && len(data) > 0 {
				return data, "sidecar-before", nil
			}
		}
	}
	if a.Disk != nil {
		data, _, err := a.Disk.ReadFile(snapshotName, guestPath, 0)
		if err != nil {
			return nil, "", err
		}
		if len(data) > 0 {
			return data, "disk", nil
		}
	}
	return nil, "", fmt.Errorf("no content for %s", guestPath)
}

func exportBaseName(guestPath string) string {
	p := strings.ReplaceAll(strings.TrimSpace(guestPath), `/`, `\`)
	base := p
	if i := strings.LastIndex(p, `\`); i >= 0 {
		base = p[i+1:]
	}
	if base == "" || base == "." {
		base = "file.bin"
	}
	var b strings.Builder
	for _, r := range base {
		switch r {
		case '<', '>', ':', '"', '/', '\\', '|', '?', '*':
			b.WriteByte('_')
		default:
			if r < 32 {
				b.WriteByte('_')
			} else {
				b.WriteRune(r)
			}
		}
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		return "file.bin"
	}
	return out
}

func copyRegularFile(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	if st.IsDir() {
		return fmt.Errorf("not a file: %s", src)
	}
	tmp := dest + ".part"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
