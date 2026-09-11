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
