package agentclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
		HTTP:    &http.Client{Timeout: 15 * time.Minute},
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
	resp, err := c.HTTP.Do(req)
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
	data, err := io.ReadAll(io.LimitReader(resp.Body, 128<<20))
	if err != nil {
		return err
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
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode agent response: %w", err)
	}
	return nil
}
