package applog

import (
	"strings"
	"sync"
	"time"
)

// Canonical levels (lowest → highest). Unknown / "cmd" map to Debug.
const (
	LevelDebug = "debug"
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"
)

// Entry is one log line for the GUI.
type Entry struct {
	Time    string `json:"time"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

// Buffer is a thread-safe ring buffer of log entries.
type Buffer struct {
	mu    sync.RWMutex
	lines []Entry
	max   int
}

// New creates a buffer retaining at most max entries.
func New(max int) *Buffer {
	if max <= 0 {
		max = 500
	}
	return &Buffer{max: max}
}

// NormalizeLevel maps aliases (cmd, warning, …) to a canonical level.
func NormalizeLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case LevelDebug, "cmd", "trace", "verbose":
		return LevelDebug
	case LevelInfo, "information", "notice", "action":
		return LevelInfo
	case LevelWarn, "warning":
		return LevelWarn
	case LevelError, "err", "fatal", "critical":
		return LevelError
	default:
		return LevelInfo
	}
}

// Rank returns a comparable rank (debug=10 … error=40).
func Rank(level string) int {
	switch NormalizeLevel(level) {
	case LevelDebug:
		return 10
	case LevelInfo:
		return 20
	case LevelWarn:
		return 30
	case LevelError:
		return 40
	default:
		return 20
	}
}

// Add appends an entry and returns it (level normalized).
func (b *Buffer) Add(level, message string) Entry {
	e := Entry{
		Time:    time.Now().Format("15:04:05"),
		Level:   NormalizeLevel(level),
		Message: message,
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lines = append(b.lines, e)
	if len(b.lines) > b.max {
		b.lines = b.lines[len(b.lines)-b.max:]
	}
	return e
}

// Lines returns a copy of buffered entries.
func (b *Buffer) Lines() []Entry {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]Entry, len(b.lines))
	copy(out, b.lines)
	return out
}

// LinesAtLeast returns entries at or above minLevel.
func (b *Buffer) LinesAtLeast(minLevel string) []Entry {
	min := Rank(minLevel)
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]Entry, 0, len(b.lines))
	for _, e := range b.lines {
		if Rank(e.Level) >= min {
			out = append(out, e)
		}
	}
	return out
}

// Clear removes all entries.
func (b *Buffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lines = nil
}
