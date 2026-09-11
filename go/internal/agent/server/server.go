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

func sysmonAvailable() bool {
	if _, err := os.Stat(`C:\Windows\Sysmon64.exe`); err == nil {
		return true
	}
	_, err := os.Stat(`C:\Windows\Sysmon.exe`)
	return err == nil
}
