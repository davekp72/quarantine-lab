//go:build !windows

package diff

func EnrichNetwork(cfgPath, projectRoot string, result *Result, fromCaptured, toCaptured string, addedSysmon []map[string]any) {
}
