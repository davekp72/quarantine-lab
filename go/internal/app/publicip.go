package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/quarantine-lab/quarantine/internal/config"
)

// PublicIPInfo is the host's apparent public egress (for VPN checks before lab launch).
type PublicIPInfo struct {
	IP       string `json:"ip"`
	ISP      string `json:"isp"`
	Org      string `json:"org"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Source   string `json:"source"`
	Warning  string `json:"warning"`
	Error    string `json:"error,omitempty"`
	LookedUp bool   `json:"lookedUp"`
	HomeISP  bool   `json:"homeIsp"`
}

// CheckHostPublicIPWails looks up the host's public IP and ISP/org.
// Used by the UI as a VPN sanity check before launching the lab VM.
func (a *App) CheckHostPublicIPWails() (map[string]any, error) {
	info := lookupPublicIP(8 * time.Second)
	var cfg *config.Config
	if a != nil {
		cfg = a.Cfg
	}
	if info.LookedUp {
		info.HomeISP = cfg.IsHomeISP(info.ISP, info.Org)
		if info.HomeISP {
			info.Warning = "This matches a configured home ISP. Turn on the VPN before malware work."
		} else {
			info.Warning = "ISP does not match a configured home provider. Confirm this is your VPN egress before malware work."
		}
	}
	out := map[string]any{
		"ip":       info.IP,
		"isp":      info.ISP,
		"org":      info.Org,
		"city":     info.City,
		"region":   info.Region,
		"country":  info.Country,
		"source":   info.Source,
		"warning":  info.Warning,
		"lookedUp": info.LookedUp,
		"homeIsp":  info.HomeISP,
	}
	if info.Error != "" {
		out["error"] = info.Error
	}
	if a != nil && a.Log != nil {
		if info.LookedUp {
			tag := "not a configured home ISP"
			if info.HomeISP {
				tag = "HOME ISP"
			}
			a.logInfo(fmt.Sprintf("Host public IP check: %s (%s) — %s", info.IP, firstNonEmpty(info.ISP, info.Org, "unknown ISP"), tag))
		} else {
			a.logInfo("Host public IP check failed: " + info.Error)
		}
	}
	return out, nil
}

// ShouldWarnPublicIPBeforeLaunchWails reports whether the UI should prompt on Launch.
func (a *App) ShouldWarnPublicIPBeforeLaunchWails() (bool, error) {
	if a == nil || a.Cfg == nil {
		return true, nil
	}
	return a.Cfg.WarnPublicIPBeforeLaunchEnabled(), nil
}

func lookupPublicIP(timeout time.Duration) PublicIPInfo {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client := &http.Client{Timeout: timeout}
	if info, ok := lookupIPInfo(ctx, client); ok {
		info.Warning = "Confirm this is your VPN egress — not your home ISP — before malware work."
		return info
	}
	if info, ok := lookupIPAPI(ctx, client); ok {
		info.Warning = "Confirm this is your VPN egress — not your home ISP — before malware work."
		return info
	}
	return PublicIPInfo{
		LookedUp: false,
		Error:    "could not determine public IP (network/VPN DNS blocked lookup?)",
		Warning:  "Public IP lookup failed. Verify your VPN is on before launching the lab VM.",
	}
}

func lookupIPInfo(ctx context.Context, client *http.Client) (PublicIPInfo, bool) {
	body, err := httpGet(ctx, client, "https://ipinfo.io/json")
	if err != nil {
		return PublicIPInfo{}, false
	}
	var raw struct {
		IP       string `json:"ip"`
		City     string `json:"city"`
		Region   string `json:"region"`
		Country  string `json:"country"`
		Org      string `json:"org"`
		Hostname string `json:"hostname"`
	}
	if err := json.Unmarshal(body, &raw); err != nil || strings.TrimSpace(raw.IP) == "" {
		return PublicIPInfo{}, false
	}
	isp := strings.TrimSpace(raw.Org)
	return PublicIPInfo{
		IP:       strings.TrimSpace(raw.IP),
		ISP:      isp,
		Org:      isp,
		City:     strings.TrimSpace(raw.City),
		Region:   strings.TrimSpace(raw.Region),
		Country:  strings.TrimSpace(raw.Country),
		Source:   "ipinfo.io",
		LookedUp: true,
	}, true
}

func lookupIPAPI(ctx context.Context, client *http.Client) (PublicIPInfo, bool) {
	// Free endpoint is HTTP-only; used as fallback.
	body, err := httpGet(ctx, client, "http://ip-api.com/json/?fields=status,message,query,isp,org,as,city,regionName,country")
	if err != nil {
		return PublicIPInfo{}, false
	}
	var raw struct {
		Status     string `json:"status"`
		Message    string `json:"message"`
		Query      string `json:"query"`
		ISP        string `json:"isp"`
		Org        string `json:"org"`
		AS         string `json:"as"`
		City       string `json:"city"`
		RegionName string `json:"regionName"`
		Country    string `json:"country"`
	}
	if err := json.Unmarshal(body, &raw); err != nil || raw.Status != "success" || strings.TrimSpace(raw.Query) == "" {
		return PublicIPInfo{}, false
	}
	isp := firstNonEmpty(strings.TrimSpace(raw.ISP), strings.TrimSpace(raw.Org), strings.TrimSpace(raw.AS))
	return PublicIPInfo{
		IP:       strings.TrimSpace(raw.Query),
		ISP:      isp,
		Org:      strings.TrimSpace(raw.Org),
		City:     strings.TrimSpace(raw.City),
		Region:   strings.TrimSpace(raw.RegionName),
		Country:  strings.TrimSpace(raw.Country),
		Source:   "ip-api.com",
		LookedUp: true,
	}, true
}

func httpGet(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "QuarantineLab/1.0")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
