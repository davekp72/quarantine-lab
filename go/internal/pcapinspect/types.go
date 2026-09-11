package pcapinspect

import (
	"net"
	"strconv"
	"strings"
	"time"
)

// ExcludeHTTPFilter drops HTTP/S (and the lab explicit-proxy ports) so this
// view complements the HTTP tab instead of duplicating it.
const ExcludeHTTPFilter = "not (http or http2 or tls or quic) and not tcp.port==80 and not tcp.port==443 and not tcp.port==8080 and not tcp.port==8081"

const maxFollowBytes = 512 * 1024
const maxFlows = 5000

// Flow is one conversation (TCP/UDP stream or endpoint pair).
type Flow struct {
	ID         string   `json:"id"`
	Transport  string   `json:"transport"`
	Protocol   string   `json:"protocol"`
	SrcIP      string   `json:"srcIp"`
	DstIP      string   `json:"dstIp"`
	SrcPort    int      `json:"srcPort"`
	DstPort    int      `json:"dstPort"`
	Stream     int      `json:"stream"`
	Packets    int      `json:"packets"`
	Bytes      int      `json:"bytes"`
	First      string   `json:"first"`
	Last       string   `json:"last"`
	Info       string   `json:"info"`
	Names      []string `json:"names,omitempty"`
	HasPayload bool     `json:"hasPayload"`
}

// FollowResult is a dissected stream / packet dump for the detail pane.
type FollowResult struct {
	ID        string   `json:"id"`
	Transport string   `json:"transport"`
	Protocol  string   `json:"protocol"`
	Filter    string   `json:"filter"`
	Node0     string   `json:"node0,omitempty"`
	Node1     string   `json:"node1,omitempty"`
	Ascii     string   `json:"ascii"`
	Hex       string   `json:"hex,omitempty"`
	Summary   []string `json:"summary,omitempty"`
	Truncated bool     `json:"truncated"`
}

type packet struct {
	t          time.Time
	protocol   string
	srcIP      string
	dstIP      string
	srcPort    int
	dstPort    int
	transport  string
	stream     int
	length     int
	info       string
	names      []string
}

var portProtocols = map[int]string{
	22:   "SSH",
	23:   "Telnet",
	25:   "SMTP",
	53:   "DNS",
	67:   "DHCP",
	68:   "DHCP",
	69:   "TFTP",
	110:  "POP3",
	123:  "NTP",
	137:  "NBNS",
	138:  "NBDS",
	139:  "SMB",
	143:  "IMAP",
	161:  "SNMP",
	162:  "SNMP",
	179:  "BGP",
	389:  "LDAP",
	445:  "SMB",
	465:  "SMTPS",
	514:  "Syslog",
	587:  "SMTP",
	636:  "LDAPS",
	993:  "IMAPS",
	995:  "POP3S",
	1433: "MSSQL",
	3306: "MySQL",
	3389: "RDP",
	5432: "PostgreSQL",
	5900: "VNC",
	9443: "Agent",
}

var genericProto = map[string]bool{
	"": true, "TCP": true, "UDP": true, "IP": true, "IPv4": true, "IPv6": true,
	"ETH": true, "ETHERNET": true, "DATA": true,
}

func atoi(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	n, _ := strconv.Atoi(s)
	return n
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func validIP(s string) bool {
	return net.ParseIP(s) != nil
}

func endpoint(ip string, port int) string {
	if ip == "" {
		return ""
	}
	if strings.Contains(ip, ":") && !strings.HasPrefix(ip, "[") {
		if port > 0 {
			return "[" + ip + "]:" + strconv.Itoa(port)
		}
		return ip
	}
	if port > 0 {
		return ip + ":" + strconv.Itoa(port)
	}
	return ip
}
