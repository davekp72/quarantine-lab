package pcapinspect

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type jsonPacket struct {
	Source struct {
		Layers map[string]any `json:"layers"`
	} `json:"_source"`
}

func parsePacketsFields(raw []byte) ([]packet, error) {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}
	out := make([]packet, 0, 256)
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		cols := strings.Split(line, "\t")
		for len(cols) < 14 {
			cols = append(cols, "")
		}
		p := packet{
			protocol: protocolFromFrameProtocols(firstCSV(cols[1])),
			srcIP:    firstNonEmpty(firstCSV(cols[2]), firstCSV(cols[4])),
			dstIP:    firstNonEmpty(firstCSV(cols[3]), firstCSV(cols[5])),
			length:   atoi(firstCSV(cols[12])),
			names:    splitCSV(cols[13]),
		}
		tcpSport := atoi(firstCSV(cols[6]))
		tcpDport := atoi(firstCSV(cols[7]))
		udpSport := atoi(firstCSV(cols[8]))
		udpDport := atoi(firstCSV(cols[9]))
		tcpStream := firstCSV(cols[10])
		udpStream := firstCSV(cols[11])
		switch {
		case tcpStream != "" || tcpSport > 0 || tcpDport > 0:
			p.transport = "tcp"
			p.srcPort = tcpSport
			p.dstPort = tcpDport
			p.stream = atoi(tcpStream)
		case udpStream != "" || udpSport > 0 || udpDport > 0:
			p.transport = "udp"
			p.srcPort = udpSport
			p.dstPort = udpDport
			p.stream = atoi(udpStream)
		default:
			p.transport = transportFromProtocol(p.protocol)
		}
		if ts := firstCSV(cols[0]); ts != "" {
			if f, err := strconvFloat(ts); err == nil {
				sec := int64(f)
				nsec := int64((f - float64(sec)) * 1e9)
				p.t = time.Unix(sec, nsec).UTC()
			}
		}
		if p.protocol == "" && p.transport != "" {
			p.protocol = strings.ToUpper(p.transport)
		}
		if p.protocol != "" || p.srcIP != "" || len(p.names) > 0 {
			out = append(out, p)
		}
	}
	return out, nil
}

func protocolFromFrameProtocols(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if i := strings.IndexByte(s, ','); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ":")
	skip := map[string]bool{
		"": true, "ETH": true, "ETHTYPE": true, "ETHERTYPE": true,
		"DATA": true, "IP": true, "IPV4": true, "IPV6": true,
	}
	for i := len(parts) - 1; i >= 0; i-- {
		p := strings.ToUpper(strings.TrimSpace(parts[i]))
		if skip[p] {
			continue
		}
		return p
	}
	return strings.ToUpper(strings.TrimSpace(parts[len(parts)-1]))
}

func firstCSV(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if i := strings.IndexByte(s, ','); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

func splitCSV(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func parsePacketsJSON(raw []byte) ([]packet, error) {
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || string(raw) == "[]" {
		return nil, nil
	}
	var rows []jsonPacket
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("tshark json: %w", err)
	}
	out := make([]packet, 0, len(rows))
	for _, row := range rows {
		if p, ok := packetFromLayers(row.Source.Layers); ok {
			out = append(out, p)
		}
	}
	return out, nil
}

func packetFromLayers(layers map[string]any) (packet, bool) {
	if len(layers) == 0 {
		return packet{}, false
	}
	p := packet{
		protocol: strings.TrimSpace(firstLayer(layers, "_ws.col.protocol", "_ws.col.Protocol")),
		srcIP:    firstNonEmpty(firstLayer(layers, "ip.src"), firstLayer(layers, "ipv6.src")),
		dstIP:    firstNonEmpty(firstLayer(layers, "ip.dst"), firstLayer(layers, "ipv6.dst")),
		info:     firstLayer(layers, "_ws.col.info", "_ws.col.Info"),
		length:   atoi(firstLayer(layers, "frame.len")),
		names:    allLayer(layers, "dns.qry.name"),
	}
	tcpSport := atoi(firstLayer(layers, "tcp.srcport"))
	tcpDport := atoi(firstLayer(layers, "tcp.dstport"))
	udpSport := atoi(firstLayer(layers, "udp.srcport"))
	udpDport := atoi(firstLayer(layers, "udp.dstport"))
	tcpStream := firstLayer(layers, "tcp.stream")
	udpStream := firstLayer(layers, "udp.stream")

	switch {
	case tcpStream != "" || tcpSport > 0 || tcpDport > 0:
		p.transport = "tcp"
		p.srcPort = tcpSport
		p.dstPort = tcpDport
		p.stream = atoi(tcpStream)
	case udpStream != "" || udpSport > 0 || udpDport > 0:
		p.transport = "udp"
		p.srcPort = udpSport
		p.dstPort = udpDport
		p.stream = atoi(udpStream)
	default:
		p.transport = transportFromProtocol(p.protocol)
	}

	if ts := firstLayer(layers, "frame.time_epoch"); ts != "" {
		if f, err := strconvFloat(ts); err == nil {
			sec := int64(f)
			nsec := int64((f - float64(sec)) * 1e9)
			p.t = time.Unix(sec, nsec).UTC()
		}
	}
	if p.protocol == "" && p.transport != "" {
		p.protocol = strings.ToUpper(p.transport)
	}
	return p, p.protocol != "" || p.srcIP != "" || p.info != ""
}

func transportFromProtocol(proto string) string {
	switch strings.ToUpper(proto) {
	case "ICMP", "ICMPV6":
		return "icmp"
	case "ARP":
		return "arp"
	case "IGMP", "IGMPV2", "IGMPV3":
		return "igmp"
	default:
		return "other"
	}
}

func strconvFloat(s string) (float64, error) {
	var f float64
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%f", &f)
	return f, err
}

func firstLayer(layers map[string]any, keys ...string) string {
	vals := allLayer(layers, keys...)
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

func allLayer(layers map[string]any, keys ...string) []string {
	var out []string
	for _, key := range keys {
		v, ok := layers[key]
		if !ok {
			v, ok = layers[strings.ToLower(key)]
		}
		if !ok {
			continue
		}
		out = append(out, flattenStrings(v)...)
	}
	return uniqueKeep(out)
}

func flattenStrings(v any) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		if strings.TrimSpace(t) == "" {
			return nil
		}
		return []string{t}
	case []string:
		var out []string
		for _, s := range t {
			if strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out
	case []any:
		var out []string
		for _, x := range t {
			out = append(out, flattenStrings(x)...)
		}
		return out
	default:
		s := strings.TrimSpace(fmt.Sprint(t))
		if s == "" || s == "<nil>" {
			return nil
		}
		return []string{s}
	}
}

func uniqueKeep(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
