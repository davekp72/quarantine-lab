package pcapinspect

import (
	"fmt"
	"strings"
)

func aggregateFlows(pkts []packet) []Flow {
	type acc struct {
		flow  Flow
		first packet
		last  packet
		seen  map[string]bool
		names []string
	}
	order := make([]string, 0, 64)
	byID := map[string]*acc{}

	for _, p := range pkts {
		id := flowID(p)
		a, ok := byID[id]
		if !ok {
			a = &acc{
				flow: Flow{
					ID:        id,
					Transport: p.transport,
					Protocol:  classifyProtocol(p),
					SrcIP:     p.srcIP,
					DstIP:     p.dstIP,
					SrcPort:   p.srcPort,
					DstPort:   p.dstPort,
					Stream:    p.stream,
					HasPayload: p.transport == "tcp" || p.transport == "udp",
				},
				first: p,
				last:  p,
				seen:  map[string]bool{},
			}
			if p.t.IsZero() {
				a.flow.First = ""
			} else {
				a.flow.First = p.t.Format("2006-01-02T15:04:05.000Z07:00")
			}
			byID[id] = a
			order = append(order, id)
		}
		a.flow.Packets++
		a.flow.Bytes += p.length
		if !p.t.IsZero() && (a.last.t.IsZero() || p.t.After(a.last.t)) {
			a.last = p
		}
		if proto := classifyProtocol(p); betterProtocol(proto, a.flow.Protocol) {
			a.flow.Protocol = proto
		}
		if p.info != "" && !a.seen[p.info] && len(a.flow.Info) < 400 {
			if a.flow.Info != "" {
				a.flow.Info += " · "
			}
			a.flow.Info += p.info
			a.seen[p.info] = true
		}
		for _, n := range p.names {
			if n == "" || a.seen["n:"+n] {
				continue
			}
			a.seen["n:"+n] = true
			a.names = append(a.names, n)
		}
	}

	out := make([]Flow, 0, len(order))
	for i, id := range order {
		if i >= maxFlows {
			break
		}
		a := byID[id]
		if !a.last.t.IsZero() {
			a.flow.Last = a.last.t.Format("2006-01-02T15:04:05.000Z07:00")
		}
		a.flow.Names = a.names
		if a.flow.Info == "" && len(a.names) > 0 {
			a.flow.Info = strings.Join(a.names, ", ")
		}
		out = append(out, a.flow)
	}
	return out
}

func flowID(p packet) string {
	switch p.transport {
	case "tcp":
		return fmt.Sprintf("tcp:%d", p.stream)
	case "udp":
		return fmt.Sprintf("udp:%d", p.stream)
	case "icmp":
		return "icmp:" + p.srcIP + ">" + p.dstIP
	case "arp":
		return "arp:" + firstNonEmpty(p.srcIP, "unknown") + ">" + firstNonEmpty(p.dstIP, "unknown")
	case "igmp":
		return "igmp:" + p.srcIP + ">" + p.dstIP
	default:
		return fmt.Sprintf("other:%s:%s>%s", strings.ToLower(p.protocol), p.srcIP, p.dstIP)
	}
}

func classifyProtocol(p packet) string {
	proto := strings.TrimSpace(p.protocol)
	if !genericProto[strings.ToUpper(proto)] {
		return proto
	}
	if mapped := portProtocols[p.dstPort]; mapped != "" {
		return mapped
	}
	if mapped := portProtocols[p.srcPort]; mapped != "" {
		return mapped
	}
	if proto != "" {
		return proto
	}
	return strings.ToUpper(p.transport)
}

func betterProtocol(candidate, current string) bool {
	if candidate == "" {
		return false
	}
	if current == "" || genericProto[strings.ToUpper(current)] {
		return !genericProto[strings.ToUpper(candidate)] || current == ""
	}
	return false
}

// DisplayFilterForID turns a flow id we minted into a tshark display filter.
func DisplayFilterForID(id string) (kind string, stream int, filter string, err error) {
	id = strings.TrimSpace(id)
	kind, rest, _ := strings.Cut(id, ":")
	kind = strings.ToLower(kind)
	switch kind {
	case "tcp", "udp":
		stream = atoi(rest)
		if rest == "" || stream < 0 || fmt.Sprintf("%d", stream) != rest {
			return "", 0, "", fmt.Errorf("invalid stream id")
		}
		return kind, stream, fmt.Sprintf("%s.stream eq %d", kind, stream), nil
	case "icmp":
		src, dst, ok := strings.Cut(rest, ">")
		if !ok || !validIP(src) || !validIP(dst) {
			return "", 0, "", fmt.Errorf("invalid icmp id")
		}
		fam := "ip"
		if strings.Contains(src, ":") {
			fam = "ipv6"
		}
		return kind, -1, fmt.Sprintf("(icmp or icmpv6) and %s.src==%s and %s.dst==%s", fam, src, fam, dst), nil
	case "arp":
		return kind, -1, "arp", nil
	case "igmp":
		src, dst, ok := strings.Cut(rest, ">")
		if !ok || !validIP(src) {
			return "", 0, "", fmt.Errorf("invalid igmp id")
		}
		dstClause := ""
		if validIP(dst) {
			dstClause = " and ip.dst==" + dst
		}
		return kind, -1, "igmp and ip.src=="+src+dstClause, nil
	case "other":
		return kind, -1, "", fmt.Errorf("cannot follow other flow")
	default:
		return "", 0, "", fmt.Errorf("unknown flow id")
	}
}
