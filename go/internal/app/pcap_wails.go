package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/httpbody"
	"github.com/quarantine-lab/quarantine/internal/pcapinspect"
)

func (a *App) evidenceNetworkDir(snapshot string) string {
	if a == nil || a.Cfg == nil {
		return ""
	}
	return a.Cfg.SidecarPath(snapshot, "-network")
}

func (a *App) evidencePcapPath(snapshot string) (string, error) {
	snapshot = strings.TrimSpace(snapshot)
	if snapshot == "" {
		return "", fmt.Errorf("snapshot name required")
	}
	dir := a.evidenceNetworkDir(snapshot)
	pcap := filepath.Join(dir, "capture.pcap")
	if _, err := os.Stat(pcap); err != nil {
		alt := filepath.Join(dir, "capture.pcapng")
		if _, err2 := os.Stat(alt); err2 == nil {
			pcap = alt
		} else {
			return "", fmt.Errorf("no capture.pcap under %s", dir)
		}
	}
	roots := a.pcapAllowRoots()
	if !httpbody.AllowedFlowPath(pcap, roots...) {
		return "", fmt.Errorf("pcap not under lab log dirs")
	}
	return pcap, nil
}

func (a *App) pcapAllowRoots() []string {
	if a == nil || a.Cfg == nil {
		return nil
	}
	return []string{
		a.Cfg.ManifestLogDir(),
		a.Cfg.Network.Capture.LogDir,
		filepath.Join(a.Cfg.DataDir(), "logs"),
	}
}

// ListPcapFlowsWails lists non-HTTP conversations from the snapshot evidence PCAP.
func (a *App) ListPcapFlowsWails(snapshotName string) (map[string]any, error) {
	pcap, err := a.evidencePcapPath(snapshotName)
	if err != nil {
		return map[string]any{
			"available": false,
			"message":   err.Error(),
			"flows":     []any{},
		}, nil
	}
	flows, err := pcapinspect.ListFlows(pcap)
	if err != nil {
		return map[string]any{
			"available": false,
			"pcap":      pcap,
			"message":   err.Error(),
			"flows":     []any{},
		}, nil
	}
	protos := map[string]int{}
	for _, f := range flows {
		protos[f.Protocol]++
	}
	return map[string]any{
		"available": true,
		"pcap":      pcap,
		"snapshot":  config.SafeSnapshotFileName(snapshotName),
		"message":   fmt.Sprintf("%d non-HTTP/S conversation(s) via tshark", len(flows)),
		"exclude":   pcapinspect.ExcludeHTTPFilter,
		"protocols": protos,
		"flows":     flows,
	}, nil
}

// InspectPcapFlowWails returns payload / dissection for one conversation.
func (a *App) InspectPcapFlowWails(snapshotName, flowID, format string) (map[string]any, error) {
	pcap, err := a.evidencePcapPath(snapshotName)
	if err != nil {
		return nil, err
	}
	res, err := pcapinspect.InspectFlow(pcap, flowID, format)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"id":        res.ID,
		"transport": res.Transport,
		"protocol":  res.Protocol,
		"filter":    res.Filter,
		"node0":     res.Node0,
		"node1":     res.Node1,
		"ascii":     res.Ascii,
		"hex":       res.Hex,
		"summary":   res.Summary,
		"truncated": res.Truncated,
	}, nil
}
