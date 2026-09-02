package disk

import (
	"encoding/xml"
	"path/filepath"
	"strings"
	"time"
)

type snapshotNode struct {
	UUID      string         `xml:"uuid,attr"`
	Name      string         `xml:"name,attr"`
	Time      string         `xml:"timeStamp,attr"`
	Hardware  hardwareNode   `xml:"Hardware"`
	Children  []snapshotNode `xml:"Snapshots>Snapshot"`
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
	mediaPaths := map[string]string{}
	walkHardDiskMedia(doc.Machine.MediaRegistry.HardDisks, vmFolder, mediaPaths)
	walkSnapshotTree(doc.Machine.RootSnapshot, out, mediaPaths)
	return out
}

func walkHardDiskMedia(nodes []hardDiskNode, vmFolder string, out map[string]string) {
	for _, n := range nodes {
		uuid := strings.ToLower(strings.Trim(n.UUID, "{}"))
		if uuid != "" && n.Location != "" {
			loc := n.Location
			if !filepath.IsAbs(loc) {
				loc = filepath.Join(vmFolder, loc)
			}
			out[uuid] = loc
		}
		walkHardDiskMedia(n.Children, vmFolder, out)
	}
}

func walkSnapshotTree(node snapshotNode, out map[string]SnapshotEntry, mediaPaths map[string]string) {
	if node.Name == "" {
		for i := range node.Children {
			walkSnapshotTree(node.Children[i], out, mediaPaths)
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
		if p, ok := mediaPaths[strings.ToLower(entry.DiskMediumUUID)]; ok {
			entry.VDIPaths = []string{p}
		}
	}
	out[strings.ToLower(node.Name)] = entry
	for i := range node.Children {
		walkSnapshotTree(node.Children[i], out, mediaPaths)
	}
}
