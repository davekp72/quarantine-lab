package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quarantine-lab/quarantine/internal/applog"
	"github.com/quarantine-lab/quarantine/internal/vbox"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) wireLogging() {
	if a.Log == nil {
		a.Log = applog.New(1000)
	}
	logFn := func(level, msg string) {
		a.emitLog(level, msg)
	}
	if a.VM != nil && a.VM.VBox != nil {
		a.VM.VBox.OnLog = logFn
	}
	if a.Evidence != nil && a.Evidence.VBox != nil {
		a.Evidence.VBox.OnLog = logFn
	}
}

func (a *App) emitLog(level, message string) {
	if a.Log == nil {
		return
	}
	entry := a.Log.Add(level, vbox.RedactSecrets(message))
	if a.WailsCtx != nil {
		runtime.EventsEmit(a.WailsCtx, "applog", entry)
	}
}

func (a *App) logInfo(msg string)  { a.emitLog("info", msg) }
func (a *App) logError(msg string) { a.emitLog("error", msg) }

// OnStartup is called when the Wails UI starts.
func (a *App) OnStartup(ctx context.Context) {
	a.WailsCtx = ctx
	a.logInfo("Quarantine Lab UI started")
}

// GetAppLogWails returns buffered activity log lines.
func (a *App) GetAppLogWails() []applog.Entry {
	if a.Log == nil {
		return nil
	}
	return a.Log.Lines()
}

// ClearAppLogWails clears the activity log buffer.
func (a *App) ClearAppLogWails() {
	if a.Log != nil {
		a.Log.Clear()
	}
	a.logInfo("Log cleared")
}

// LogFileInfo describes a host log file for the log viewer.
type LogFileInfo struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Modified string `json:"modified"`
	Source   string `json:"source"`
}

// ListLogFilesWails lists recent log-like files from configured log directories.
func (a *App) ListLogFilesWails() ([]LogFileInfo, error) {
	type dirSource struct {
		source string
		dir    string
	}
	dirs := []dirSource{
		{"manifests", a.Cfg.ManifestLogDir()},
		{"proxy", a.Cfg.Network.Proxy.LogDir},
		{"pcap", a.Cfg.Network.Capture.LogDir},
		{"inbox", a.Cfg.Inbox.LogDir},
	}
	var files []LogFileInfo
	seen := map[string]bool{}
	for _, ds := range dirs {
		dir := strings.TrimSpace(ds.dir)
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			a.emitLog("debug", fmt.Sprintf("log dir unavailable (%s): %s", ds.source, dir))
			continue
		}
		for _, ent := range entries {
			if ent.IsDir() {
				continue
			}
			name := ent.Name()
			lower := strings.ToLower(name)
			if !strings.HasSuffix(lower, ".log") &&
				!strings.HasSuffix(lower, ".txt") &&
				!strings.HasSuffix(lower, ".json") &&
				!strings.HasSuffix(lower, ".pcapng") {
				continue
			}
			info, err := ent.Info()
			if err != nil {
				continue
			}
			path := filepath.Join(dir, name)
			if seen[path] {
				continue
			}
			seen[path] = true
			files = append(files, LogFileInfo{
				Name:     name,
				Path:     path,
				Size:     info.Size(),
				Modified: info.ModTime().Format(time.RFC3339),
				Source:   ds.source,
			})
		}
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].Modified > files[j].Modified
	})
	if len(files) > 40 {
		files = files[:40]
	}
	return files, nil
}

// TailLogFileWails returns the last maxLines lines of a host log file.
func (a *App) TailLogFileWails(path string, maxLines int) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("log path required")
	}
	if maxLines <= 0 {
		maxLines = 400
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	const maxBytes = 512 * 1024
	stat, err := f.Stat()
	if err != nil {
		return "", err
	}
	size := stat.Size()
	start := int64(0)
	if size > maxBytes {
		start = size - maxBytes
	}
	if start > 0 {
		if _, err := f.Seek(start, io.SeekStart); err != nil {
			return "", err
		}
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	text := string(raw)
	if start > 0 {
		if idx := strings.Index(text, "\n"); idx >= 0 {
			text = text[idx+1:]
		}
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return strings.Join(lines, "\n"), nil
}
