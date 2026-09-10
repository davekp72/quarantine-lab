//go:build windows

package collectors

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/quarantine-lab/quarantine/internal/agent/privileges"
	"golang.org/x/sys/windows"
)

var (
	modWevtapi    = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery  = modWevtapi.NewProc("EvtQuery")
	procEvtNext   = modWevtapi.NewProc("EvtNext")
	procEvtRender = modWevtapi.NewProc("EvtRender")
	procEvtClose  = modWevtapi.NewProc("EvtClose")
)

const (
	evtQueryChannelPath = 0x1
	evtRenderEventXml   = 1
)

var sysmonEventIDs = map[int]string{
	1: "ProcessCreate", 2: "FileCreateTime", 3: "NetworkConnect",
	11: "FileCreate", 12: "RegistryEvent", 13: "RegistryEvent",
	15: "FileCreateStreamHash", 22: "DnsQuery", 23: "FileDelete",
	26: "FileDeleteDetected",
}

// SysmonEvents reads Sysmon operational log since baselineAt.
func SysmonEvents(logName, baselineAt string, maxEvents int) (json.RawMessage, int, error) {
	_ = privileges.EnableManifestRead()
	if logName == "" {
		logName = `Microsoft-Windows-Sysmon/Operational`
	}
	if maxEvents <= 0 {
		maxEvents = 50000
	}
	available := sysmonRunning()
	if !available {
		out, _ := json.Marshal(map[string]any{
			"available": false, "eventCount": 0,
			"message": "Sysmon not running", "events": []any{},
		})
		return out, 0, nil
	}

	since := parseBaselineTime(baselineAt)
	query := buildTimeQuery(since)
	events, err := queryEvents(logName, query, maxEvents, normalizeSysmonEvent)
	if err != nil {
		out, _ := json.Marshal(map[string]any{
			"available": false, "eventCount": 0,
			"message": err.Error(), "events": []any{},
		})
		return out, 0, nil
	}
	out, _ := json.Marshal(map[string]any{
		"available":  true,
		"eventCount": len(events),
		"recordedAt": time.Now().UTC().Format(time.RFC3339),
		"baselineAt": baselineAt,
		"logName":    logName,
		"events":     events,
	})
	if len(events) == 0 {
		if psEvents, psErr := sysmonEventsPowerShell(logName, baselineAt, maxEvents); psErr == nil && len(psEvents) > 0 {
			events = psEvents
			out, _ = json.Marshal(map[string]any{
				"available":  true,
				"eventCount": len(events),
				"recordedAt": time.Now().UTC().Format(time.RFC3339),
				"baselineAt": baselineAt,
				"logName":    logName,
				"events":     events,
				"source":     "powershell",
			})
		}
	}
	return out, len(events), nil
}

// ServiceInstallEvents reads System log 7045 since baselineAt.
func ServiceInstallEvents(baselineAt string, maxEvents int) (json.RawMessage, int, error) {
	_ = privileges.EnableManifestRead()
	if maxEvents <= 0 {
		maxEvents = 500
	}
	since := parseBaselineTime(baselineAt)
	query := fmt.Sprintf(`*[System[Provider[@Name='Service Control Manager'] and EventID=7045 and TimeCreated[@SystemTime>='%s']]]`, since)
	events, err := queryEvents("System", query, maxEvents, normalizeServiceEvent)
	if err != nil {
		out, _ := json.Marshal(map[string]any{
			"available": false, "eventCount": 0,
			"message": err.Error(), "events": []any{},
		})
		return out, 0, nil
	}
	out, _ := json.Marshal(map[string]any{
		"available":  true,
		"eventCount": len(events),
		"recordedAt": time.Now().UTC().Format(time.RFC3339),
		"baselineAt": baselineAt,
		"events":     events,
	})
	return out, len(events), nil
}

func sysmonRunning() bool {
	out, err := exec.Command("powershell.exe", "-NoProfile", "-Command",
		`(Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue).Status -eq 'Running'`).CombinedOutput()
	if err == nil && strings.TrimSpace(string(out)) == "True" {
		return true
	}
	if _, err := os.Stat(`C:\Windows\Sysmon64.exe`); err == nil {
		return true
	}
	_, err = os.Stat(`C:\Windows\Sysmon.exe`)
	return err == nil
}

func parseBaselineTime(baselineAt string) string {
	if baselineAt == "" {
		return time.Now().UTC().Add(-24 * time.Hour).Format("2006-01-02T15:04:05.0000000Z")
	}
	t, err := time.Parse(time.RFC3339, baselineAt)
	if err != nil {
		return baselineAt
	}
	return t.UTC().Format("2006-01-02T15:04:05.0000000Z")
}

func buildTimeQuery(since string) string {
	ids := []string{"1", "2", "11", "12", "13", "15", "22", "23", "26"}
	var parts []string
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf("EventID=%s", id))
	}
	idFilter := strings.Join(parts, " or ")
	return fmt.Sprintf(`*[System[(%s) and TimeCreated[@SystemTime>='%s']]]`, idFilter, since)
}

type eventXML struct {
	System struct {
		EventID     string `xml:"EventID"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Computer string `xml:"Computer"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

func queryEvents(channel, xpath string, maxEvents int, normalize func(eventXML, map[string]string) map[string]any) ([]map[string]any, error) {
	ch, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return nil, err
	}
	q, err := windows.UTF16PtrFromString(xpath)
	if err != nil {
		return nil, err
	}
	r0, _, e1 := procEvtQuery.Call(0, uintptr(unsafe.Pointer(ch)), uintptr(unsafe.Pointer(q)), evtQueryChannelPath)
	if r0 == 0 {
		return nil, fmt.Errorf("EvtQuery: %v", e1)
	}
	handle := syscall.Handle(r0)
	defer procEvtClose.Call(uintptr(handle))

	var events []map[string]any
	const batch = 64
	handles := make([]syscall.Handle, batch)

	for len(events) < maxEvents {
		var returned uint32
		r0, _, e1 := procEvtNext.Call(
			uintptr(handle), batch, uintptr(unsafe.Pointer(&handles[0])), 5000, 0, uintptr(unsafe.Pointer(&returned)),
		)
		if r0 == 0 || returned == 0 {
			break
		}
		if e1 != nil && e1.Error() != "The operation completed successfully." && returned == 0 {
			break
		}
		for i := uint32(0); i < returned && len(events) < maxEvents; i++ {
			xmlStr, err := renderEventXML(handles[i])
			procEvtClose.Call(uintptr(handles[i]))
			if err != nil {
				continue
			}
			var ev eventXML
			if err := xml.Unmarshal([]byte(xmlStr), &ev); err != nil {
				continue
			}
			fields := map[string]string{}
			for _, d := range ev.EventData.Data {
				if d.Name != "" {
					fields[d.Name] = d.Value
				}
			}
			events = append(events, normalize(ev, fields))
		}
	}
	return events, nil
}

func renderEventXML(h syscall.Handle) (string, error) {
	var bufUsed, propCount uint32
	r0, _, e1 := procEvtRender.Call(0, uintptr(h), evtRenderEventXml, 0, 0, 0, uintptr(unsafe.Pointer(&bufUsed)))
	if bufUsed == 0 {
		return "", fmt.Errorf("EvtRender size: %v", e1)
	}
	buf := make([]uint16, bufUsed/2+1)
	r0, _, e1 = procEvtRender.Call(0, uintptr(h), evtRenderEventXml, uintptr(bufUsed), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&bufUsed)), uintptr(unsafe.Pointer(&propCount)))
	if r0 == 0 {
		return "", fmt.Errorf("EvtRender: %v", e1)
	}
	return windows.UTF16ToString(buf), nil
}

func normalizeSysmonEvent(ev eventXML, data map[string]string) map[string]any {
	eid := 0
	fmt.Sscanf(ev.System.EventID, "%d", &eid)
	typ := sysmonEventIDs[eid]
	if typ == "" {
		typ = fmt.Sprintf("Event%d", eid)
	}
	out := map[string]any{
		"eid":            eid,
		"t":              typ,
		"time":           ev.System.TimeCreated.SystemTime,
		"computer":       ev.System.Computer,
		"image":          data["Image"],
		"commandLine":    data["CommandLine"],
		"processGuid":    data["ProcessGuid"],
		"processId":      data["ProcessId"],
		"targetObject":   data["TargetObject"],
		"details":        data["Details"],
		"queryName":      data["QueryName"],
		"queryResults":   data["QueryResults"],
		"targetFilename": data["TargetFilename"],
		"target":         data["TargetFilename"],
		"hashes":         data["Hashes"],
	}
	return out
}

func normalizeServiceEvent(ev eventXML, data map[string]string) map[string]any {
	msg := data["Message"]
	serviceName := data["ServiceName"]
	imagePath := data["ImagePath"]
	if msg == "" {
		msg = fmt.Sprintf("Service %s installed", serviceName)
	}
	return map[string]any{
		"eid":         7045,
		"t":           "ServiceInstall",
		"time":        ev.System.TimeCreated.SystemTime,
		"computer":    ev.System.Computer,
		"serviceName": serviceName,
		"imagePath":   imagePath,
		"summary":     msg,
	}
}
