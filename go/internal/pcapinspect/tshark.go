package pcapinspect

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// FindTshark returns the tshark executable path.
func FindTshark() (string, error) {
	if p := strings.TrimSpace(os.Getenv("TSHARK")); p != "" {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	if p, err := exec.LookPath("tshark"); err == nil {
		return p, nil
	}
	if runtime.GOOS == "windows" {
		for _, c := range []string{
			filepath.Join(os.Getenv("ProgramFiles"), "Wireshark", "tshark.exe"),
			filepath.Join(os.Getenv("ProgramFiles(x86)"), "Wireshark", "tshark.exe"),
		} {
			if st, err := os.Stat(c); err == nil && !st.IsDir() {
				return c, nil
			}
		}
	}
	return "", fmt.Errorf("tshark not found (install Wireshark)")
}

func runTshark(tshark string, timeout time.Duration, args ...string) ([]byte, error) {
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	ctxArgs := append([]string{}, args...)
	cmd := exec.Command(tshark, ctxArgs...)
	hideConsole(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			msg := strings.TrimSpace(stderr.String())
			if msg == "" {
				msg = err.Error()
			}
			return stdout.Bytes(), fmt.Errorf("tshark: %s", truncate(msg, 300))
		}
		return stdout.Bytes(), nil
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("tshark timed out after %s", timeout)
	}
}

// ListFlows groups non-HTTP packets from a PCAP into conversations.
func ListFlows(pcapPath string) ([]Flow, error) {
	tshark, err := FindTshark()
	if err != nil {
		return nil, err
	}
	pcapPath = filepath.Clean(pcapPath)
	if st, err := os.Stat(pcapPath); err != nil || st.IsDir() {
		return nil, fmt.Errorf("pcap not found: %s", pcapPath)
	}
	out, err := runTshark(tshark, 90*time.Second,
		"-r", pcapPath,
		"-Y", ExcludeHTTPFilter,
		"-T", "json",
		"-e", "frame.time_epoch",
		"-e", "_ws.col.Protocol",
		"-e", "ip.src",
		"-e", "ip.dst",
		"-e", "ipv6.src",
		"-e", "ipv6.dst",
		"-e", "tcp.srcport",
		"-e", "tcp.dstport",
		"-e", "udp.srcport",
		"-e", "udp.dstport",
		"-e", "tcp.stream",
		"-e", "udp.stream",
		"-e", "frame.len",
		"-e", "dns.qry.name",
		"-e", "_ws.col.Info",
	)
	if err != nil {
		return nil, err
	}
	pkts, err := parsePacketsJSON(out)
	if err != nil {
		return nil, err
	}
	return aggregateFlows(pkts), nil
}

// InspectFlow returns ascii (and optional hex) payload plus packet info lines.
func InspectFlow(pcapPath, flowID, format string) (*FollowResult, error) {
	tshark, err := FindTshark()
	if err != nil {
		return nil, err
	}
	pcapPath = filepath.Clean(pcapPath)
	kind, stream, filter, err := DisplayFilterForID(flowID)
	if err != nil {
		return nil, err
	}
	res := &FollowResult{
		ID:        flowID,
		Transport: kind,
		Filter:    filter,
	}

	sumOut, err := runTshark(tshark, 45*time.Second,
		"-r", pcapPath,
		"-Y", filter,
		"-T", "fields",
		"-E", "separator=|",
		"-e", "frame.number",
		"-e", "_ws.col.Protocol",
		"-e", "_ws.col.Info",
	)
	if err != nil {
		return nil, err
	}
	res.Summary = parseSummaryLines(sumOut, 80)
	if len(res.Summary) > 0 {
		parts := strings.SplitN(res.Summary[0], " | ", 3)
		if len(parts) >= 2 {
			res.Protocol = parts[1]
		}
	}

	wantHex := strings.EqualFold(format, "hex") || strings.EqualFold(format, "both")
	if kind == "tcp" || kind == "udp" {
		asciiOut, err := runTshark(tshark, 45*time.Second, "-r", pcapPath, "-q", "-z",
			fmt.Sprintf("follow,%s,ascii,%d", kind, stream))
		if err != nil {
			return nil, err
		}
		parsed := parseFollow(asciiOut)
		res.Node0, res.Node1 = parsed.node0, parsed.node1
		res.Ascii, res.Truncated = capText(parsed.body, maxFollowBytes)
		if wantHex {
			hexOut, herr := runTshark(tshark, 45*time.Second, "-r", pcapPath, "-q", "-z",
				fmt.Sprintf("follow,%s,hex,%d", kind, stream))
			if herr != nil {
				return nil, herr
			}
			hexParsed := parseFollow(hexOut)
			res.Hex, res.Truncated = capText(hexParsed.body, maxFollowBytes)
		}
		return res, nil
	}

	// Non-stream protocols: join info lines as the "payload".
	res.Ascii, res.Truncated = capText(strings.Join(res.Summary, "\n"), maxFollowBytes)
	return res, nil
}

type followParsed struct {
	node0, node1, body string
}

func parseFollow(raw []byte) followParsed {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	var p followParsed
	lines := strings.Split(text, "\n")
	bodyStart := 0
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "Node 0:") {
			p.node0 = strings.TrimSpace(strings.TrimPrefix(trim, "Node 0:"))
		}
		if strings.HasPrefix(trim, "Node 1:") {
			p.node1 = strings.TrimSpace(strings.TrimPrefix(trim, "Node 1:"))
			bodyStart = i + 1
			break
		}
	}
	if bodyStart == 0 {
		p.body = strings.TrimSpace(text)
		return p
	}
	p.body = strings.TrimSpace(strings.Join(lines[bodyStart:], "\n"))
	return p
}

func parseSummaryLines(raw []byte, limit int) []string {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		out = append(out, strings.Join(parts, " | "))
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

func capText(s string, n int) (string, bool) {
	if n <= 0 || len(s) <= n {
		return s, false
	}
	return s[:n] + "\n… truncated …", true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
