package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/quarantine-lab/quarantine/internal/agent/guestpaths"
	"github.com/quarantine-lab/quarantine/internal/agent/types"
)

func TestHandleFilesRejectsWindowsPaths(t *testing.T) {
	s := New("tok", types.AgentConfig{PayloadUser: "analyst", LabAdmin: "quarantine"})
	u := "/v1/files?path=" + url.QueryEscape(`C:\Windows\System32\cmd.exe`)
	r := httptest.NewRequest(http.MethodPut, u, bytes.NewReader([]byte("x")))
	w := httptest.NewRecorder()
	s.handleFiles(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("put system32: %d %s", w.Code, w.Body.String())
	}

	r = httptest.NewRequest(http.MethodGet, "/v1/files", nil)
	w = httptest.NewRecorder()
	s.handleFiles(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing path: %d", w.Code)
	}
}

func TestHandleFilesRoundTripPublic(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("guest paths are Windows")
	}
	dir := guestpaths.PublicDir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Skip(err)
	}
	path := filepath.Join(dir, "qlab-agent-files-test.bin")
	defer os.Remove(path)
	s := New("tok", types.AgentConfig{})
	body := []byte("quarantine-agent-files-test")
	u := "/v1/files?path=" + url.QueryEscape(path)
	r := httptest.NewRequest(http.MethodPut, u, bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleFiles(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("put: %d %s", w.Code, w.Body.String())
	}
	r = httptest.NewRequest(http.MethodGet, u, nil)
	w = httptest.NewRecorder()
	s.handleFiles(w, r)
	if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), body) {
		t.Fatalf("get: %d %q", w.Code, w.Body.Bytes())
	}
	r = httptest.NewRequest(http.MethodDelete, u, nil)
	w = httptest.NewRecorder()
	s.handleFiles(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
}

func TestHandleExecRequiresAbsolute(t *testing.T) {
	s := New("tok", types.AgentConfig{})
	r := httptest.NewRequest(http.MethodPost, "/v1/exec", bytes.NewReader([]byte(`{"exe":"cmd.exe"}`)))
	w := httptest.NewRecorder()
	s.handleExec(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("relative exe: %d %s", w.Code, w.Body.String())
	}
}
