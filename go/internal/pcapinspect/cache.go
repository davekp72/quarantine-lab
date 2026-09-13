package pcapinspect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// flowCacheVersion bumps when ListFlows field set / aggregation changes.
const flowCacheVersion = 1

const flowCacheName = "traffic-flows.json"

type flowCacheDoc struct {
	Version int    `json:"version"`
	Pcap    string `json:"pcap"`
	Size    int64  `json:"size"`
	ModNano int64  `json:"modTimeUnixNano"`
	Flows   []Flow `json:"flows"`
}

func flowCachePath(pcapPath string) string {
	return filepath.Join(filepath.Dir(pcapPath), flowCacheName)
}

func loadFlowCache(pcapPath string, st os.FileInfo) ([]Flow, bool) {
	raw, err := os.ReadFile(flowCachePath(pcapPath))
	if err != nil {
		return nil, false
	}
	var doc flowCacheDoc
	if json.Unmarshal(raw, &doc) != nil {
		return nil, false
	}
	if doc.Version != flowCacheVersion || doc.Size != st.Size() || doc.ModNano != st.ModTime().UnixNano() {
		return nil, false
	}
	if doc.Flows == nil {
		doc.Flows = []Flow{}
	}
	return cloneFlows(doc.Flows), true
}

func saveFlowCache(pcapPath string, st os.FileInfo, flows []Flow) {
	doc := flowCacheDoc{
		Version: flowCacheVersion,
		Pcap:    filepath.Base(pcapPath),
		Size:    st.Size(),
		ModNano: st.ModTime().UnixNano(),
		Flows:   flows,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return
	}
	_ = os.WriteFile(flowCachePath(pcapPath), raw, 0o644)
}

func cloneFlows(in []Flow) []Flow {
	out := make([]Flow, len(in))
	copy(out, in)
	for i := range out {
		if in[i].Names != nil {
			out[i].Names = append([]string(nil), in[i].Names...)
		}
	}
	return out
}

// WarmFlowCache runs ListFlows (or hits an existing cache) for each PCAP path.
// Compare uses this so the Traffic tab does not start tshark again.
func WarmFlowCache(pcapPaths ...string) (ok int) {
	seen := map[string]bool{}
	for _, p := range pcapPaths {
		p = filepath.Clean(strings.TrimSpace(p))
		if p == "" || p == "." || seen[p] {
			continue
		}
		seen[p] = true
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if _, err := ListFlows(p); err == nil {
			ok++
		}
	}
	return ok
}
