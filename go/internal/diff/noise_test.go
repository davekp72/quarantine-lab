package diff

import (
	"testing"

	"github.com/quarantine-lab/quarantine/internal/evidence"
)

func TestIsFileNoise(t *testing.T) {
	if !IsFileNoise(FileDetail{Path: `C:\Users\x\AppData\Local\Microsoft\EdgeUpdate\Ready`}) {
		t.Fatal("EdgeUpdate should be noise")
	}
	if !IsFileNoise(FileDetail{Path: `C:\Windows\Temp\foo.txt`}) {
		t.Fatal("Temp txt should be noise")
	}
	if IsFileNoise(FileDetail{Path: `C:\Windows\Temp\evil.exe`}) {
		t.Fatal("high-signal exe in Temp is not noise")
	}
	if IsFileNoise(FileDetail{Path: `C:\payload\drop.exe`}) {
		t.Fatal("payload exe is not noise")
	}
	if IsFileNoisePatterns(FileDetail{Path: `C:\Windows\Temp\foo.txt`}, []string{}) {
		t.Fatal("empty file list should not treat Temp as noise")
	}
	if !IsFileNoisePatterns(FileDetail{Path: `C:\payload\keep\note.txt`}, []string{`\payload\keep\`}) {
		t.Fatal("custom file pattern")
	}
	if !IsFileNoise(FileDetail{
		Path: `C:\Users\x\AppData\Local\Microsoft\Edge\User Data\EBWebView\Default\Cache\data_0`,
		Size: 100,
	}) {
		t.Fatal("small EBWebView cache is noise")
	}
	if IsFileNoise(FileDetail{
		Path: `C:\Users\x\AppData\Local\Microsoft\Edge\User Data\EBWebView\Default\Cache\blob`,
		Size: 2 * 1024 * 1024,
	}) {
		t.Fatal("2MiB EBWebView cache is kept")
	}
}

func TestIsNetworkHostNoise(t *testing.T) {
	if !IsNetworkHostNoise("settings-win.data.microsoft.com") {
		t.Fatal("microsoft host")
	}
	if !IsNetworkHostNoise("https://ctldl.windowsupdate.com/msdownload/update") {
		t.Fatal("windowsupdate url")
	}
	if IsNetworkHostNoise("evil.test") {
		t.Fatal("evil.test is signal")
	}
	if !IsNetworkHostNoise("home.arpa") {
		t.Fatal("lab host")
	}
}

func TestIsNetworkHostNoiseCustomDomains(t *testing.T) {
	if IsNetworkHostNoiseDomains("evil.test", []string{"example.com"}) {
		t.Fatal("evil.test should not match custom list")
	}
	if !IsNetworkHostNoiseDomains("a.evil.test", []string{"evil.test"}) {
		t.Fatal("suffix match")
	}
	if IsNetworkHostNoiseDomains("microsoft.com", []string{}) {
		t.Fatal("empty list should not treat microsoft.com as noise")
	}
	if !IsNetworkHostNoiseDomains("localhost", []string{}) {
		t.Fatal("lab host still noise")
	}
}

func TestFilterResultNoiseOffVsOn(t *testing.T) {
	in := sampleNoisyResult()
	off := FilterResult(in, false)
	on := FilterResult(in, true)
	if in.Summary.FilesAdded != 2 {
		t.Fatalf("FilterResult must not mutate input: added=%d", in.Summary.FilesAdded)
	}
	if off == nil || on == nil {
		t.Fatal("nil result")
	}
	if off.Summary.FilesAdded != 2 || off.Summary.FilesModified != 1 {
		t.Fatalf("noise-off files added=%d modified=%d", off.Summary.FilesAdded, off.Summary.FilesModified)
	}
	if on.Summary.FilesAdded != 1 || on.Summary.FilesModified != 1 {
		t.Fatalf("noise-on files added=%d modified=%d", on.Summary.FilesAdded, on.Summary.FilesModified)
	}
	if on.Files.Added[0].Path != `C:\payload\drop.exe` {
		t.Fatalf("kept %q", on.Files.Added[0].Path)
	}
	if len(on.Network.DNS) != 1 || on.Network.DNS[0]["query"] != "evil.test" {
		t.Fatalf("dns=%v", on.Network.DNS)
	}
	if len(on.Network.Requests) != 1 || on.Network.Requests[0]["host"] != "evil.test" {
		t.Fatalf("http=%v", on.Network.Requests)
	}
	if len(on.Sysmon.Added) != 1 {
		t.Fatalf("sysmon=%d", len(on.Sysmon.Added))
	}
	if len(on.USN.Events) != 1 {
		t.Fatalf("usn=%d", len(on.USN.Events))
	}
	if len(on.Registry.Added) != 1 {
		t.Fatalf("payload registry should stay: %d", len(on.Registry.Added))
	}
	if on.Registry.Added[0].K != `HKCU\Software\Payload` {
		t.Fatalf("kept %q", on.Registry.Added[0].K)
	}
	if off.Summary.DNSQueries != 2 || on.Summary.DNSQueries != 1 {
		t.Fatalf("dns counts off=%d on=%d", off.Summary.DNSQueries, on.Summary.DNSQueries)
	}

	in.Network.Requests[0]["flowFile"] = "orig-flow"
	on.Network.Requests[0]["flowFile"] = "mutated"
	if in.Network.Requests[0]["flowFile"] != "orig-flow" {
		t.Fatal("filter must not mutate live request maps")
	}

	custom := FilterResultWith(in, true, []string{"evil.test"}, nil, nil)
	if custom.Summary.DNSQueries != 1 || custom.Network.DNS[0]["query"] != "settings-win.data.microsoft.com" {
		t.Fatalf("custom domains should keep microsoft DNS: %v", custom.Network.DNS)
	}
}

func TestIsRegistryNoise(t *testing.T) {
	if !IsRegistryNoise(`HKCU\Software\Microsoft\Windows\CurrentVersion\IrisService\Cache\foo`, nil) {
		t.Fatal("IrisService should be default noise")
	}
	if IsRegistryNoise(`HKCU\Software\Payload`, nil) {
		t.Fatal("payload key is not noise")
	}
	if IsRegistryNoise(`HKCU\Software\Microsoft\Windows\CurrentVersion\IrisService\Cache\foo`, []string{}) {
		t.Fatal("empty list should keep IrisService")
	}
	if !IsRegistryNoise(`HKLM\Software\Evil\Run`, []string{`\Evil\`}) {
		t.Fatal("custom registry pattern")
	}
}

func TestFilterResultRegistryNoise(t *testing.T) {
	in := &Result{
		Registry: RegistrySection{
			Added: []evidence.RegistryEntry{
				{K: `HKCU\Software\Payload`, N: "Run"},
				{K: `HKCU\Software\Microsoft\Windows\CurrentVersion\IrisService\Cache\x`, N: "v"},
			},
		},
	}
	on := FilterResult(in, true)
	if len(on.Registry.Added) != 1 || on.Registry.Added[0].K != `HKCU\Software\Payload` {
		t.Fatalf("default registry filter: %#v", on.Registry.Added)
	}
	if on.Summary.RegistryVolatileFiltered < 1 {
		t.Fatalf("volatile filtered=%d", on.Summary.RegistryVolatileFiltered)
	}
	empty := FilterResultWith(in, true, nil, nil, []string{})
	if len(empty.Registry.Added) != 2 {
		t.Fatalf("empty registry list should keep both: %d", len(empty.Registry.Added))
	}
	off := FilterResult(in, false)
	if len(off.Registry.Added) != 2 {
		t.Fatalf("hide-noise off should keep IrisService: %d", len(off.Registry.Added))
	}
}

func sampleNoisyResult() *Result {
	return &Result{
		Meta: MetaSection{FromSnapshot: "CleanSession", ToSnapshot: "Evidence-test"},
		Files: FilesSection{
			Added: []FileDetail{
				{Path: `C:\payload\drop.exe`, Size: 100, Hash: "aa"},
				{Path: `C:\Windows\Temp\foo.txt`, Size: 4},
			},
			Modified: []FileModified{
				{Path: `C:\payload\note.txt`, Before: FileDetail{Path: `C:\payload\note.txt`, Size: 1}, After: FileDetail{Path: `C:\payload\note.txt`, Size: 2}},
			},
		},
		Registry: RegistrySection{
			Added: []evidence.RegistryEntry{
				{K: `HKCU\Software\Payload`, N: "Run", T: "REG_SZ", V: "x"},
				{K: `HKCU\Software\Microsoft\Windows\CurrentVersion\IrisService\Cache\x`, N: "v"},
			},
		},
		Sysmon: SysmonSection{
			Added: []map[string]any{
				{"image": `C:\payload\drop.exe`, "summary": "Process Create"},
				{"image": `C:\Users\x\AppData\Local\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe`, "summary": "Process Create"},
			},
		},
		USN: &USNSection{
			Events: []map[string]any{
				{"fileName": `C:\payload\drop.exe`},
				{"fileName": `C:\Windows\Temp\foo.txt`},
			},
		},
		Network: &NetworkSection{
			DNS: []map[string]any{
				{"query": "evil.test"},
				{"query": "settings-win.data.microsoft.com"},
			},
			Requests: []map[string]any{
				{"host": "evil.test", "url": "https://evil.test/", "flowFile": `Z:\logs\Evidence-test-network\flows.jsonl`},
				{"host": "microsoft.com", "url": "https://microsoft.com/"},
			},
		},
		Summary: SummarySection{FilesAdded: 2, FilesModified: 1},
	}
}
