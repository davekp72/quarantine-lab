package app

import (
	"fmt"
	"strings"

	"github.com/quarantine-lab/quarantine/internal/config"
)

func boolPtr(v bool) *bool { return &v }

func (a *App) uiSettingsMap() map[string]any {
	cfg := a.Cfg
	if cfg == nil {
		cfg = &config.Config{}
	}
	patterns := cfg.HomeISPPatterns()
	domains := cfg.NoiseDomains()
	files := cfg.NoiseFiles()
	registry := cfg.NoiseRegistry()
	return map[string]any{
		"filePreviewMaxKb":         cfg.FilePreviewMaxKBResolved(),
		"filePreviewMaxBytes":      cfg.FilePreviewMaxBytes(),
		"contentMaxKb":             cfg.ContentMaxKBResolved(),
		"hashMaxMb":                cfg.HashMaxMBResolved(),
		"totalEmbedMaxMb":          cfg.TotalEmbedMaxMBResolved(),
		"hideRoutineNoise":         cfg.HideRoutineNoiseEnabled(),
		"refreshOnCompare":         cfg.RefreshOnCompareEnabled(),
		"warnPublicIpBeforeLaunch": cfg.WarnPublicIPBeforeLaunchEnabled(),
		"homeIspPatterns":          patterns,
		"homeIspPatternsText":      strings.Join(patterns, ", "),
		"noiseDomains":             domains,
		"noiseDomainsText":         strings.Join(domains, "\n"),
		"defaultNoiseDomains":      append([]string{}, config.DefaultNoiseDomains...),
		"noiseFiles":               files,
		"noiseFilesText":           strings.Join(files, "\n"),
		"defaultNoiseFiles":        append([]string{}, config.DefaultNoiseFiles...),
		"noiseRegistry":            registry,
		"noiseRegistryText":        strings.Join(registry, "\n"),
		"defaultNoiseRegistry":     append([]string{}, config.DefaultNoiseRegistry...),
	}
}

// UISettingsWails returns desktop + capture settings for the Settings dialog.
func (a *App) UISettingsWails() (map[string]any, error) {
	if a == nil {
		return (&App{Cfg: &config.Config{}}).uiSettingsMap(), nil
	}
	if a.Cfg == nil {
		a.Cfg = &config.Config{}
	}
	return a.uiSettingsMap(), nil
}

// SetUISettingsWails applies Settings immediately and persists them to quarantine-vm.json.
// Noise lists are saved from their own windows (SetNoiseDomainsWails / SetNoiseFilesWails / SetNoiseRegistryWails).
func (a *App) SetUISettingsWails(
	filePreviewMaxKb int,
	hideRoutineNoise bool,
	refreshOnCompare bool,
	warnPublicIP bool,
	homeIspPatterns string,
	contentMaxKb int,
	hashMaxMb int,
	totalEmbedMaxMb int,
) (map[string]any, error) {
	if a == nil || a.Cfg == nil {
		return nil, fmt.Errorf("config unavailable")
	}
	a.Cfg.UI.FilePreviewMaxKB = filePreviewMaxKb
	a.Cfg.UI.HideRoutineNoise = boolPtr(hideRoutineNoise)
	a.Cfg.UI.RefreshOnCompare = boolPtr(refreshOnCompare)
	a.Cfg.UI.WarnPublicIPBeforeLaunch = boolPtr(warnPublicIP)
	a.Cfg.UI.HomeISPPatterns = config.ParseHomeISPPatterns(homeIspPatterns)
	a.Cfg.Manifest.ContentMaxKB = contentMaxKb
	a.Cfg.Manifest.HashMaxMB = hashMaxMb
	a.Cfg.Manifest.TotalEmbedMaxMB = totalEmbedMaxMb
	if err := a.Cfg.PersistUI(a.ConfigPath); err != nil {
		a.logError("Save settings: " + err.Error())
		return a.uiSettingsMap(), fmt.Errorf("applied for this session; save failed: %w", err)
	}
	a.logInfo(fmt.Sprintf(
		"Settings saved: preview=%d KiB contentEmbed=%d KiB hash=%d MiB totalEmbed=%d MiB hideNoise=%v refresh=%v warnIP=%v homeIsp=%q",
		a.Cfg.FilePreviewMaxKBResolved(),
		a.Cfg.ContentMaxKBResolved(),
		a.Cfg.HashMaxMBResolved(),
		a.Cfg.TotalEmbedMaxMBResolved(),
		a.Cfg.HideRoutineNoiseEnabled(),
		a.Cfg.RefreshOnCompareEnabled(),
		a.Cfg.WarnPublicIPBeforeLaunchEnabled(),
		strings.Join(a.Cfg.HomeISPPatterns(), ", "),
	))
	return a.uiSettingsMap(), nil
}

// SetNoiseDomainsWails saves the Hide-noise host suffix list.
func (a *App) SetNoiseDomainsWails(text string) (map[string]any, error) {
	if a == nil || a.Cfg == nil {
		return nil, fmt.Errorf("config unavailable")
	}
	a.Cfg.UI.NoiseDomains = config.ParseNoiseDomains(text)
	if err := a.Cfg.PersistUI(a.ConfigPath); err != nil {
		a.logError("Save noise domains: " + err.Error())
		return a.uiSettingsMap(), fmt.Errorf("applied for this session; save failed: %w", err)
	}
	a.logInfo(fmt.Sprintf("Noise domains saved: %d", len(a.Cfg.NoiseDomains())))
	return a.uiSettingsMap(), nil
}

// SetNoiseFilesWails saves the Hide-noise guest-path substring list.
func (a *App) SetNoiseFilesWails(text string) (map[string]any, error) {
	if a == nil || a.Cfg == nil {
		return nil, fmt.Errorf("config unavailable")
	}
	a.Cfg.UI.NoiseFiles = config.ParseNoiseFiles(text)
	if err := a.Cfg.PersistUI(a.ConfigPath); err != nil {
		a.logError("Save file noise: " + err.Error())
		return a.uiSettingsMap(), fmt.Errorf("applied for this session; save failed: %w", err)
	}
	a.logInfo(fmt.Sprintf("File noise saved: %d", len(a.Cfg.NoiseFiles())))
	return a.uiSettingsMap(), nil
}

// SetNoiseRegistryWails saves the Hide-noise registry-key substring list.
func (a *App) SetNoiseRegistryWails(text string) (map[string]any, error) {
	if a == nil || a.Cfg == nil {
		return nil, fmt.Errorf("config unavailable")
	}
	a.Cfg.UI.NoiseRegistry = config.ParseNoiseRegistry(text)
	if err := a.Cfg.PersistUI(a.ConfigPath); err != nil {
		a.logError("Save registry noise: " + err.Error())
		return a.uiSettingsMap(), fmt.Errorf("applied for this session; save failed: %w", err)
	}
	a.logInfo(fmt.Sprintf("Registry noise saved: %d", len(a.Cfg.NoiseRegistry())))
	return a.uiSettingsMap(), nil
}
