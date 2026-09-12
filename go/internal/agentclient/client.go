package agentclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quarantine-lab/quarantine/internal/agent/types"
	"github.com/quarantine-lab/quarantine/internal/config"
)

// Client talks to the quarantine-agent HTTP API inside the VM.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func New(cfg *config.Config) (*Client, error) {
	if !cfg.Agent.Enabled {
		return nil, fmt.Errorf("agent not enabled in config")
	}
	token, err := cfg.AgentToken()
	if err != nil {
		return nil, err
	}
	host := strings.TrimSpace(cfg.Agent.Host)
	if host == "" {
		host = "127.0.0.1"
	}
	port := cfg.Agent.Port
	if port <= 0 {
		port = 9443
	}
	return &Client{
		BaseURL: fmt.Sprintf("http://%s:%d", host, port),
		Token:   token,
		HTTP:    &http.Client{Timeout: 30 * time.Minute},
	}, nil
}

func (c *Client) Health(ctx context.Context) (*types.HealthResponse, error) {
	var out types.HealthResponse
	if err := c.get(ctx, "/health", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Capture(ctx context.Context, req types.CaptureRequest) (*types.CaptureResponse, error) {
	var out types.CaptureResponse
	if err := c.post(ctx, "/v1/capture", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) DownloadHive(ctx context.Context, guestPath, dest string) error {
	u := c.BaseURL + "/v1/hives?path=" + url.QueryEscape(guestPath)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("agent hive download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		msg := strings.TrimSpace(string(data))
		if msg == "" {
			msg = resp.Status
		}
		return fmt.Errorf("agent HTTP %d: %s", resp.StatusCode, msg)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("write hive %s: %w", dest, err)
	}
	return nil
}

func (c *Client) DeleteHiveDir(ctx context.Context, guestDir string) error {
	u := c.BaseURL + "/v1/hives?dir=" + url.QueryEscape(guestDir)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("agent hive delete: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		msg := strings.TrimSpace(string(data))
		if msg == "" {
			msg = resp.Status
		}
		return fmt.Errorf("agent HTTP %d: %s", resp.StatusCode, msg)
	}
	return nil
}

func (c *Client) PutFile(ctx context.Context, guestPath, hostPath string) error {
	f, err := os.Open(hostPath)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size() > types.FileMaxBytes {
		return fmt.Errorf("file exceeds 64 MiB")
	}
	u := c.BaseURL + "/v1/files?path=" + url.QueryEscape(guestPath)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, f)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.ContentLength = st.Size()
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("agent put file: %w", err)
	}
	defer resp.Body.Close()
	return decodeStatus(resp)
}

func (c *Client) GetFile(ctx context.Context, guestPath, dest string) error {
	data, err := c.GetFileBytes(ctx, guestPath, types.FileMaxBytes)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dest, data, 0o644)
}

// GetFileBytes downloads an allowlisted guest file into memory (capped).
func (c *Client) GetFileBytes(ctx context.Context, guestPath string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 || maxBytes > types.FileMaxBytes {
		maxBytes = types.FileMaxBytes
	}
	u := c.BaseURL + "/v1/files?path=" + url.QueryEscape(guestPath)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("agent get file: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, decodeStatus(resp)
	}
	limited := io.LimitReader(resp.Body, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read agent file: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return data[:maxBytes], nil
	}
	return data, nil
}

func (c *Client) DeleteFile(ctx context.Context, guestPath string) error {
	u := c.BaseURL + "/v1/files?path=" + url.QueryEscape(guestPath)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("agent delete file: %w", err)
	}
	defer resp.Body.Close()
	return decodeStatus(resp)
}

func (c *Client) Exec(ctx context.Context, reqBody types.ExecRequest) (*types.ExecResponse, error) {
	var out types.ExecResponse
	if err := c.post(ctx, "/v1/exec", reqBody, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func decodeStatus(resp *http.Response) error {
	if resp.StatusCode < 400 {
		return nil
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	msg := strings.TrimSpace(string(data))
	if msg == "" {
		msg = resp.Status
	}
	return fmt.Errorf("agent HTTP %d: %s", resp.StatusCode, msg)
}

func (c *Client) Baseline(ctx context.Context) (json.RawMessage, error) {
	var out struct {
		Baseline json.RawMessage `json:"baseline"`
	}
	if err := c.post(ctx, "/v1/baseline", map[string]any{}, &out); err != nil {
		return nil, err
	}
	return out.Baseline, nil
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	client := c.HTTP
	if _, hasDeadline := ctx.Deadline(); hasDeadline && client != nil {
		// Honour short UI/status deadlines instead of the capture-oriented client timeout.
		client = &http.Client{Timeout: 0, Transport: client.Transport}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("agent request: %w", err)
	}
	defer resp.Body.Close()
	return decode(resp, out)
}

func (c *Client) post(ctx context.Context, path string, body any, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("agent request: %w", err)
	}
	defer resp.Body.Close()
	return decode(resp, out)
}

func decode(resp *http.Response, out any) error {
	const maxBody = 512 << 20 // 512 MiB
	limited := io.LimitReader(resp.Body, maxBody+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(data) > maxBody {
		return fmt.Errorf("agent response exceeds %d MiB (truncated); reduce contentMaxKb or changed-file capture", maxBody>>20)
	}
	if resp.StatusCode >= 400 {
		msg := strings.TrimSpace(string(data))
		if msg == "" {
			msg = resp.Status
		}
		return fmt.Errorf("agent HTTP %d: %s", resp.StatusCode, msg)
	}
	if out == nil {
		return nil
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return fmt.Errorf("decode agent response: empty body (HTTP %s) — agent may have crashed or timed out during capture", resp.Status)
	}
	if err := json.Unmarshal(data, out); err != nil {
		preview := string(data)
		if len(preview) > 240 {
			preview = preview[:120] + "…" + preview[len(preview)-120:]
		}
		return fmt.Errorf("decode agent response: %w (len=%d preview=%q)", err, len(data), preview)
	}
	return nil
}
