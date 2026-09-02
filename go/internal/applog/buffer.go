package applog

import (
	"sync"
	"time"
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

// Add appends an entry and returns it.
func (b *Buffer) Add(level, message string) Entry {
	e := Entry{
		Time:    time.Now().Format("15:04:05"),
		Level:   level,
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

// Clear removes all entries.
func (b *Buffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lines = nil
}
