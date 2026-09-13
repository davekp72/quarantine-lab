package pcapinspect

import (
	"bytes"
	"context"
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

func tsharkFastArgs(args []string) []string {
	if len(args) > 0 && args[0] == "-n" {
		return args
	}
	out := make([]string, 0, len(args)+1)
	out = append(out, "-n")
	return append(out, args...)
}

type lineLimitWriter struct {
	limit  int
	lines  int
	buf    *bytes.Buffer
	cancel context.CancelFunc
	hit    bool
}

func (w *lineLimitWriter) Write(p []byte) (int, error) {
	if w.hit {
		return len(p), nil
	}
	_, _ = w.buf.Write(p)
	w.lines += bytes.Count(p, []byte("\n"))
	if w.limit > 0 && w.lines >= w.limit {
		w.hit = true
		if w.cancel != nil {
			w.cancel()
		}
	}
	return len(p), nil
}

func runTshark(tshark string, timeout time.Duration, args ...string) ([]byte, error) {
	return runTsharkLimited(tshark, timeout, 0, args...)
}

func runTsharkLimited(tshark string, timeout time.Duration, maxLines int, args ...string) ([]byte, error) {
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, tshark, tsharkFastArgs(args)...)
	hideConsole(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stderr = &stderr
	limiter := &lineLimitWriter{limit: maxLines, buf: &stdout, cancel: cancel}
	if maxLines > 0 {
		cmd.Stdout = limiter
	} else {
		cmd.Stdout = &stdout
	}
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("tshark timed out after %s", timeout)
	}
	if maxLines > 0 && limiter.hit && stdout.Len() > 0 {
		return stdout.Bytes(), nil
	}
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return stdout.Bytes(), fmt.Errorf("tshark: %s", truncate(msg, 300))
	}
	return stdout.Bytes(), nil
}

// ListFlows groups non-HTTP packets from a PCAP into conversations.
func ListFlows(pcapPath string) ([]Flow, error) {
	flows, _, err := ListFlowsCached(pcapPath)
	return flows, err
}

// ListFlowsCached is ListFlows plus whether the result came from traffic-flows.json.
func ListFlowsCached(pcapPath string) ([]Flow, bool, error) {
	pcapPath = filepath.Clean(pcapPath)
	st, err := os.Stat(pcapPath)
	if err != nil || st.IsDir() {
		return nil, false, fmt.Errorf("pcap not found: %s", pcapPath)
	}
	if flows, ok := loadFlowCache(pcapPath, st); ok {
		return flows, true, nil
	}
	tshark, err := FindTshark()
	if err != nil {
		return nil, false, err
	}
	// Fields + no name resolution. JSON + _ws.col.* on a full gateway
	// capture is what made the Traffic tab time out.
	out, err := runTshark(tshark, 90*time.Second,
		"-r", pcapPath,
		"-Y", ExcludeHTTPFilter,
		"-T", "fields",
		"-E", "header=n",
		"-E", "separator=\t",
		"-E", "occurrence=a",
		"-E", "aggregator=,",
		"-e", "frame.time_epoch",
		"-e", "frame.protocols",
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
	)
	if err != nil {
		return nil, false, err
	}
	pkts, err := parsePacketsFields(out)
	if err != nil {
		return nil, false, err
	}
	flows := aggregateFlows(pkts)
	saveFlowCache(pcapPath, st, flows)
	return cloneFlows(flows), false, nil
}

// InspectFlow returns ascii, hex, or packet-info for one conversation.
// format is ascii (default), hex, or summary — only that pass is run.
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
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "ascii"
	}

	loadSummary := func() error {
		sumOut, err := runTsharkLimited(tshark, 45*time.Second, 80,
			"-r", pcapPath,
			"-Y", filter,
			"-T", "fields",
			"-E", "separator=|",
			"-e", "frame.number",
			"-e", "frame.protocols",
			"-e", "dns.qry.name",
		)
		if err != nil {
			return err
		}
		res.Summary = parseSummaryLines(sumOut, 80)
		for i, line := range res.Summary {
			parts := strings.SplitN(line, " | ", 3)
			if len(parts) >= 2 {
				parts[1] = protocolFromFrameProtocols(parts[1])
				res.Summary[i] = strings.Join(parts, " | ")
			}
		}
		if len(res.Summary) > 0 {
			parts := strings.SplitN(res.Summary[0], " | ", 3)
			if len(parts) >= 2 {
				res.Protocol = parts[1]
			}
		}
		return nil
	}

	if kind != "tcp" && kind != "udp" {
		if err := loadSummary(); err != nil {
			return nil, err
		}
		res.Ascii, res.Truncated = capText(strings.Join(res.Summary, "\n"), maxFollowBytes)
		return res, nil
	}

	if format == "summary" {
		if err := loadSummary(); err != nil {
			return nil, err
		}
		return res, nil
	}

	followFmt := "ascii"
	if format == "hex" || format == "both" {
		followFmt = "hex"
	}
	followOut, err := runTshark(tshark, 45*time.Second, "-r", pcapPath, "-q", "-z",
		fmt.Sprintf("follow,%s,%s,%d", kind, followFmt, stream))
	if err != nil {
		return nil, err
	}
	parsed := parseFollow(followOut)
	res.Node0, res.Node1 = parsed.node0, parsed.node1
	body, trunc := capText(parsed.body, maxFollowBytes)
	res.Truncated = trunc
	if followFmt == "hex" {
		res.Hex = body
	} else {
		res.Ascii = body
	}
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
