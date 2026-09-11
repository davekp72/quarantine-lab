package disk

import (
	"strings"
	"testing"
)

const sampleVBoxFragment = `<?xml version="1.0"?>
<VirtualBox>
  <Machine>
    <MediaRegistry>
      <HardDisks>
        <HardDisk uuid="{42e3a748-b86a-4097-9b0d-e9a1de8e8713}" location="Quarantine-Win11.vdi">
          <HardDisk uuid="{8015754e-afc4-4aea-b8fb-75e100364d28}" location="Snapshots/{8015754e-afc4-4aea-b8fb-75e100364d28}.vdi">
            <HardDisk uuid="{ba6463f7-dabb-4aad-b03d-f040b6e1bd73}" location="Snapshots/{ba6463f7-dabb-4aad-b03d-f040b6e1bd73}.vdi"/>
          </HardDisk>
        </HardDisk>
      </HardDisks>
    </MediaRegistry>
    <Snapshot uuid="{70c05276-413c-45d3-9c66-25c1dabb8438}" name="Clean" timeStamp="2026-09-02T14:40:27Z">
      <Hardware>
        <StorageControllers>
          <StorageController name="SATA">
            <AttachedDevice type="HardDisk">
              <Image uuid="{42e3a748-b86a-4097-9b0d-e9a1de8e8713}"/>
            </AttachedDevice>
          </StorageController>
        </StorageControllers>
      </Hardware>
      <Snapshots>
        <Snapshot uuid="{14bdc0b0-6050-4a74-bd4b-4f7d1a9e8936}" name="CleanSession" timeStamp="2026-09-02T19:14:14Z">
          <Hardware>
            <StorageControllers>
              <StorageController name="SATA">
                <AttachedDevice type="HardDisk">
                  <Image uuid="{8015754e-afc4-4aea-b8fb-75e100364d28}"/>
                </AttachedDevice>
              </StorageController>
            </StorageControllers>
          </Hardware>
          <Snapshots>
            <Snapshot uuid="{0f7e0ff7-8ac3-4297-ac5f-7f6b72e2103d}" name="Evidence-20260902-202548" timeStamp="2026-09-02T19:25:49Z">
              <Hardware>
                <StorageControllers>
                  <StorageController name="SATA">
                    <AttachedDevice type="HardDisk">
                      <Image uuid="{ba6463f7-dabb-4aad-b03d-f040b6e1bd73}"/>
                    </AttachedDevice>
                  </StorageController>
                </StorageControllers>
              </Hardware>
            </Snapshot>
          </Snapshots>
        </Snapshot>
      </Snapshots>
    </Snapshot>
  </Machine>
</VirtualBox>`

func TestParseSnapshotIndexNested(t *testing.T) {
	idx := parseSnapshotIndex([]byte(sampleVBoxFragment), `C:\QuarantineLab\Quarantine-Win11`)
	ev, ok := idx["evidence-20260902-202548"]
	if !ok {
		t.Fatalf("missing evidence snapshot: %#v", idx)
	}
	if ev.DiskMediumUUID != "ba6463f7-dabb-4aad-b03d-f040b6e1bd73" {
		t.Fatalf("medium uuid: %q", ev.DiskMediumUUID)
	}
	if len(ev.VDIPaths) != 1 || !strings.Contains(ev.VDIPaths[0], "ba6463f7") {
		t.Fatalf("vdi paths: %#v", ev.VDIPaths)
	}
	clean, ok := idx["cleansession"]
	if !ok || clean.DiskMediumUUID != "8015754e-afc4-4aea-b8fb-75e100364d28" {
		t.Fatalf("cleansession: %#v", clean)
	}
}
