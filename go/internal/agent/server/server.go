package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/quarantine-lab/quarantine/internal/agent/capture"
	"github.com/quarantine-lab/quarantine/internal/agent/cmdexec"
	"github.com/quarantine-lab/quarantine/internal/agent/collectors"
	"github.com/quarantine-lab/quarantine/internal/agent/guestpaths"
	"github.com/quarantine-lab/quarantine/internal/agent/types"
)

const defaultPort = 9443

// Server is the guest HTTP API.
type Server struct {
	Token      string
	Config     types.AgentConfig
	started    time.Time
	mu         sync.Mutex
	httpServer *http.Server
}

func New(token string, cfg types.AgentConfig) *Server {
	if cfg.Port <= 0 {
		cfg.Port = defaultPort
	}
	return &Server{Token: token, Config: cfg, started: time.Now()}
}

func (s *Server) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.auth(s.handleHealth))
	mux.HandleFunc("/v1/baseline", s.auth(s.handleBaseline))
	mux.HandleFunc("/v1/capture", s.auth(s.handleCapture))
	mux.HandleFunc("/v1/hives", s.auth(s.handleHives))
	mux.HandleFunc("/v1/files", s.auth(s.handleFiles))
	mux.HandleFunc("/v1/exec", s.auth(s.handleExec))

	addr := fmt.Sprintf(":%d", s.Config.Port)
	s.httpServer = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       30 * time.Minute,
		WriteTimeout:      30 * time.Minute,
	}
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		if token == "" || token != s.Token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	active, user := collectors.PayloadSessionActive(s.Config.PayloadUser)
	usnOK := collectors.USNAvailable()
	resp := types.HealthResponse{
		Version:           types.Version,
		UptimeSec:         int64(time.Since(s.started).Seconds()),
		ComputerName:      os.Getenv("COMPUTERNAME"),
		SysmonAvailable:   sysmonAvailable(),
		USNAvailable:      usnOK,
		CaptureReady:      usnOK,
		PayloadSession:    active,
		PayloadUser:       s.Config.PayloadUser,
		PayloadUserLogged: user,
	}
	writeJSON(w, resp)
}

func (s *Server) handleBaseline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bl, err := collectors.Baseline(collectors.DefaultVolume())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"baseline": json.RawMessage(bl)})
}

func (s *Server) handleCapture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req types.CaptureRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp, err := capture.Run(req, s.Config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONCompact(w, resp)
}

func (s *Server) handleHives(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.serveHiveFile(w, r)
	case http.MethodDelete:
		s.deleteHiveDir(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) serveHiveFile(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSpace(r.URL.Query().Get("path"))
	if path == "" {
		snap := r.URL.Query().Get("snapshot")
		name := r.URL.Query().Get("file")
		resolved, err := guestpaths.HiveFilePath(snap, name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		path = resolved
	}
	if !guestpaths.IsHivePath(path) {
		http.Error(w, "refusing path outside hive root", http.StatusForbidden)
		return
	}
	st, err := os.Lstat(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if st.Mode()&os.ModeSymlink != 0 || st.IsDir() {
		http.Error(w, "hive path must be a regular file", http.StatusForbidden)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", st.Size()))
	_, _ = io.Copy(w, f)
}

func (s *Server) deleteHiveDir(w http.ResponseWriter, r *http.Request) {
	dir := strings.TrimSpace(r.URL.Query().Get("dir"))
	if dir == "" {
		snap := strings.TrimSpace(r.URL.Query().Get("snapshot"))
		if snap == "" {
			http.Error(w, "dir or snapshot is required", http.StatusBadRequest)
			return
		}
		dir = guestpaths.HiveDir(snap)
	}
	if !guestpaths.ShouldDeleteHiveDir(dir) {
		http.Error(w, "refusing to delete path outside hive roots", http.StatusForbidden)
		return
	}
	if err := os.RemoveAll(dir); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeJSONCompact(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) filePolicy() guestpaths.FilePolicy {
	return guestpaths.FilePolicy{
		PayloadUser: s.Config.PayloadUser,
		LabAdmin:    s.Config.LabAdmin,
		SysmonDir:   s.Config.SysmonDir,
	}
}

func (s *Server) handleFiles(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSpace(r.URL.Query().Get("path"))
	if path == "" {
		http.Error(w, "path is required", http.StatusBadRequest)
		return
	}
	pol := s.filePolicy()
	switch r.Method {
	case http.MethodGet:
		if err := pol.AllowedFile(path, guestpaths.FileGet); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		s.serveRegularFile(w, path)
	case http.MethodPut:
		if err := pol.AllowedFile(path, guestpaths.FilePut); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if r.ContentLength > types.FileMaxBytes {
			http.Error(w, "file exceeds 64 MiB", http.StatusRequestEntityTooLarge)
			return
		}
		if err := os.MkdirAll(filepathDir(path), 0o755); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		limited := io.LimitReader(r.Body, types.FileMaxBytes+1)
		data, err := io.ReadAll(limited)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if int64(len(data)) > types.FileMaxBytes {
			http.Error(w, "file exceeds 64 MiB", http.StatusRequestEntityTooLarge)
			return
		}
		if err := writeGuestFile(path, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		if err := pol.AllowedFile(path, guestpaths.FileDelete); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		st, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if st.Mode()&os.ModeSymlink != 0 {
			http.Error(w, "refusing to delete symlink", http.StatusForbidden)
			return
		}
		if st.IsDir() {
			err = os.RemoveAll(path)
		} else {
			err = os.Remove(path)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) serveRegularFile(w http.ResponseWriter, path string) {
	st, err := os.Lstat(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if st.Mode()&os.ModeSymlink != 0 || st.IsDir() {
		http.Error(w, "path must be a regular file", http.StatusForbidden)
		return
	}
	if st.Size() > types.FileMaxBytes {
		http.Error(w, "file exceeds 64 MiB", http.StatusRequestEntityTooLarge)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", st.Size()))
	_, _ = io.Copy(w, f)
}

func filepathDir(p string) string {
	p = strings.ReplaceAll(p, `/`, `\`)
	i := strings.LastIndex(p, `\`)
	if i <= 0 {
		return p
	}
	return p[:i]
}

// writeGuestFile replaces path, clearing the read-only attribute when present.
// FirstLogon-staged scripts under Public\Quarantine are often read-only.
func writeGuestFile(path string, data []byte) error {
	if st, err := os.Stat(path); err == nil {
		if st.Mode()&0o222 == 0 {
			_ = os.Chmod(path, st.Mode()|0o644)
		}
		_ = os.Remove(path)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		tmp := path + ".qlab-new"
		_ = os.Remove(tmp)
		if werr := os.WriteFile(tmp, data, 0o644); werr != nil {
			return err
		}
		if rerr := os.Rename(tmp, path); rerr != nil {
			_ = os.Remove(tmp)
			return err
		}
	}
	return nil
}

func (s *Server) handleExec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req types.ExecRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Exe = strings.TrimSpace(req.Exe)
	if req.Exe == "" {
		http.Error(w, "exe is required", http.StatusBadRequest)
		return
	}
	if err := s.filePolicy().AllowedExec(req.Exe); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	resp := cmdexec.Run(req, s.Config)
	if resp.Error != "" && resp.ExitCode == -1 && strings.Contains(resp.Error, "not allowed") {
		http.Error(w, resp.Error, http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func sysmonAvailable() bool {
	if _, err := os.Stat(`C:\Windows\Sysmon64.exe`); err == nil {
		return true
	}
	_, err := os.Stat(`C:\Windows\Sysmon.exe`)
	return err == nil
}
