package app

import (
	"fmt"
	"strings"

	"github.com/quarantine-lab/quarantine/internal/config"
)

func boolPtr(v bool) *bool { return &v }

func (a *App) uiSettingsMap() map[string]any {
	cfg := a.Cfg
	patterns := cfg.HomeISPPatterns()
	return map[string]any{
		"filePreviewMaxKb":         cfg.FilePreviewMaxKBResolved(),
		"filePreviewMaxBytes":      cfg.FilePreviewMaxBytes(),
		"hideRoutineNoise":         cfg.HideRoutineNoiseEnabled(),
		"refreshOnCompare":         cfg.RefreshOnCompareEnabled(),
		"warnPublicIpBeforeLaunch": cfg.WarnPublicIPBeforeLaunchEnabled(),
		"homeIspPatterns":          patterns,
		"homeIspPatternsText":      strings.Join(patterns, ", "),
	}
}

// UISettingsWails returns desktop Defaults for the sidebar.
func (a *App) UISettingsWails() (map[string]any, error) {
	if a == nil {
		return (&App{Cfg: &config.Config{}}).uiSettingsMap(), nil
	}
	if a.Cfg == nil {
		a.Cfg = &config.Config{}
	}
	return a.uiSettingsMap(), nil
}

// SetUISettingsWails applies Defaults immediately and persists them to quarantine-vm.json.
func (a *App) SetUISettingsWails(filePreviewMaxKb int, hideRoutineNoise bool, refreshOnCompare bool, warnPublicIP bool, homeIspPatterns string) (map[string]any, error) {
	if a == nil || a.Cfg == nil {
		return nil, fmt.Errorf("config unavailable")
	}
	a.Cfg.UI.FilePreviewMaxKB = filePreviewMaxKb
	a.Cfg.UI.HideRoutineNoise = boolPtr(hideRoutineNoise)
	a.Cfg.UI.RefreshOnCompare = boolPtr(refreshOnCompare)
	a.Cfg.UI.WarnPublicIPBeforeLaunch = boolPtr(warnPublicIP)
	a.Cfg.UI.HomeISPPatterns = config.ParseHomeISPPatterns(homeIspPatterns)
	if err := a.Cfg.PersistUI(a.ConfigPath); err != nil {
		a.logError("Save defaults: " + err.Error())
		return a.uiSettingsMap(), fmt.Errorf("applied for this session; save failed: %w", err)
	}
	a.logInfo(fmt.Sprintf(
		"Defaults saved: preview=%d KiB hideNoise=%v refresh=%v warnIP=%v homeIsp=%q",
		a.Cfg.FilePreviewMaxKBResolved(),
		a.Cfg.HideRoutineNoiseEnabled(),
		a.Cfg.RefreshOnCompareEnabled(),
		a.Cfg.WarnPublicIPBeforeLaunchEnabled(),
		strings.Join(a.Cfg.HomeISPPatterns(), ", "),
	))
	return a.uiSettingsMap(), nil
}
