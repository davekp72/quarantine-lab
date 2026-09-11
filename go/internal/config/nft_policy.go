package config

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

func uniqueSortedPorts(ports []int) []int {
	seen := map[int]bool{}
	var out []int
	for _, p := range ports {
		if p < 1 || p > 65535 || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

func nftPortSet(ports []int) string {
	ports = uniqueSortedPorts(ports)
	if len(ports) == 0 {
		return ""
	}
	if len(ports) == 1 {
		return strconv.Itoa(ports[0])
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

// PermissiveForwardRules is injected into nftables.conf at __PERMISSIVE_WAN_RULES__.
// Placeholders __LAN__/__WAN__ are substituted on the gateway.
func (p PermissivePolicy) PermissiveForwardRules() string {
	p = p.WithDefaults()
	var b strings.Builder
	if p.ICMP() {
		b.WriteString("    iifname \"__LAN__\" oifname \"__WAN__\" ip protocol icmp accept\n")
		b.WriteString("    iifname \"__LAN__\" oifname \"__WAN__\" ip6 nexthdr icmpv6 accept\n")
	}
	if p.ForceDNS() {
		b.WriteString("    # DNS / DoT to WAN blocked — redirected to gateway in prerouting\n")
		b.WriteString("    iifname \"__LAN__\" oifname \"__WAN__\" udp dport { 53, 853 } drop\n")
		b.WriteString("    iifname \"__LAN__\" oifname \"__WAN__\" tcp dport { 53, 853 } drop\n")
	}
	var tcpWAN, udpWAN []int
	for _, port := range uniqueSortedPorts(p.TCPPorts) {
		if port == 80 || port == 443 {
			continue // MITM redirect; WAN 80/443 already dropped
		}
		tcpWAN = append(tcpWAN, port)
	}
	for _, port := range uniqueSortedPorts(p.UDPPorts) {
		if p.ForceDNS() && (port == 53 || port == 853) {
			continue
		}
		if port == 80 || port == 443 {
			continue
		}
		udpWAN = append(udpWAN, port)
	}
	if set := nftPortSet(tcpWAN); set != "" {
		b.WriteString(fmt.Sprintf("    iifname \"__LAN__\" oifname \"__WAN__\" tcp dport %s accept\n", set))
	}
	if set := nftPortSet(udpWAN); set != "" {
		b.WriteString(fmt.Sprintf("    iifname \"__LAN__\" oifname \"__WAN__\" udp dport %s accept\n", set))
	}
	b.WriteString("    # No blanket LAN→WAN accept — remaining traffic is dropped (policy drop).\n")
	return b.String()
}

// PermissiveNATRules is injected at __PERMISSIVE_DNS_NAT__.
func (p PermissivePolicy) PermissiveNATRules() string {
	p = p.WithDefaults()
	if !p.ForceDNS() {
		return "    # forceDnsToGateway off — guest DNS to public resolvers may use WAN if UDP/TCP 53 is allowlisted\n"
	}
	return "" +
		"    # Force guest DNS onto the gateway (dnsmasq / FakeNet listener)\n" +
		"    iifname \"__LAN__\" udp dport 53 redirect to :53\n" +
		"    iifname \"__LAN__\" tcp dport 53 redirect to :53\n"
}
