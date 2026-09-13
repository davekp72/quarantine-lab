package disk

import (
	"encoding/xml"
	"path/filepath"
	"strings"
	"time"
)

type snapshotNode struct {
	UUID     string         `xml:"uuid,attr"`
	Name     string         `xml:"name,attr"`
	Time     string         `xml:"timeStamp,attr"`
	Hardware hardwareNode   `xml:"Hardware"`
	Children []snapshotNode `xml:"Snapshots>Snapshot"`
}

type hardwareNode struct {
	StorageControllers []storageControllerNode `xml:"StorageControllers>StorageController"`
}

type storageControllerNode struct {
	AttachedDevices []attachedDeviceNode `xml:"AttachedDevice"`
}

type attachedDeviceNode struct {
	Type  string    `xml:"type,attr"`
	Image imageNode `xml:"Image"`
}

type imageNode struct {
	UUID string `xml:"uuid,attr"`
}

type hardDiskNode struct {
	UUID     string         `xml:"uuid,attr"`
	Location string         `xml:"location,attr"`
	Children []hardDiskNode `xml:"HardDisk"`
}

func (s snapshotNode) diskMediumUUID() string {
	for _, sc := range s.Hardware.StorageControllers {
		for _, ad := range sc.AttachedDevices {
			if strings.EqualFold(ad.Type, "HardDisk") {
				return strings.Trim(ad.Image.UUID, "{}")
			}
		}
	}
	return ""
}

// mediaInfo is one HardDisk in the .vbox MediaRegistry tree.
type mediaInfo struct {
	Path       string
	ParentUUID string
}

func parseSnapshotIndex(raw []byte, vmFolder string) map[string]SnapshotEntry {
	out := map[string]SnapshotEntry{}
	var doc struct {
		Machine struct {
			MediaRegistry struct {
				HardDisks []hardDiskNode `xml:"HardDisks>HardDisk"`
			} `xml:"MediaRegistry"`
			RootSnapshot snapshotNode `xml:"Snapshot"`
		} `xml:"Machine"`
	}
	if err := xml.Unmarshal(raw, &doc); err != nil {
		return out
	}
	media := map[string]mediaInfo{}
	walkHardDiskMedia(doc.Machine.MediaRegistry.HardDisks, vmFolder, "", media)
	walkSnapshotTree(doc.Machine.RootSnapshot, out, media)
	return out
}

func walkHardDiskMedia(nodes []hardDiskNode, vmFolder, parentUUID string, out map[string]mediaInfo) {
	for _, n := range nodes {
		uuid := strings.ToLower(strings.Trim(n.UUID, "{}"))
		if uuid != "" && n.Location != "" {
			loc := n.Location
			if !filepath.IsAbs(loc) {
				loc = filepath.Join(vmFolder, loc)
			}
			out[uuid] = mediaInfo{Path: loc, ParentUUID: parentUUID}
		}
		nextParent := uuid
		if nextParent == "" {
			nextParent = parentUUID
		}
		walkHardDiskMedia(n.Children, vmFolder, nextParent, out)
	}
}

// mediaChain returns VDI paths from the snapshot leaf toward the base disk.
func mediaChain(leafUUID string, media map[string]mediaInfo) []string {
	var paths []string
	seen := map[string]bool{}
	uuid := strings.ToLower(strings.Trim(leafUUID, "{}"))
	for uuid != "" && !seen[uuid] {
		seen[uuid] = true
		info, ok := media[uuid]
		if !ok {
			break
		}
		if info.Path != "" {
			paths = append(paths, info.Path)
		}
		uuid = info.ParentUUID
	}
	return paths
}

func walkSnapshotTree(node snapshotNode, out map[string]SnapshotEntry, media map[string]mediaInfo) {
	if node.Name == "" {
		for i := range node.Children {
			walkSnapshotTree(node.Children[i], out, media)
		}
		return
	}
	entry := SnapshotEntry{
		Name:           node.Name,
		UUID:           node.UUID,
		DiskMediumUUID: node.diskMediumUUID(),
	}
	if t, err := time.Parse(time.RFC3339Nano, node.Time); err == nil {
		entry.Time = t
	}
	if entry.DiskMediumUUID != "" {
		entry.VDIPaths = mediaChain(entry.DiskMediumUUID, media)
	}
	out[strings.ToLower(node.Name)] = entry
	for i := range node.Children {
		walkSnapshotTree(node.Children[i], out, media)
	}
}
