package pcapinspect

import (
	"fmt"
	"net"
	"strings"

	"github.com/quarantine-lab/quarantine/internal/config"
)

// AnnotatePolicyBreaches flags flows that would be denied by the permissive allowlist.
// FakeNet does not use this (all traffic is sinkholed). LAN/gateway destinations are allowed.
func AnnotatePolicyBreaches(flows []Flow, pol config.PermissivePolicy, lanCIDR, gatewayIP, guestIP string) {
	pol = pol.WithDefaults()
	_, lanNet, _ := net.ParseCIDR(strings.TrimSpace(lanCIDR))
	gw := net.ParseIP(strings.TrimSpace(gatewayIP))
	guest := net.ParseIP(strings.TrimSpace(guestIP))
	tcpOK := portSet(pol.TCPPorts)
	udpOK := portSet(pol.UDPPorts)
	tcpOK[80] = true
	tcpOK[443] = true

	for i := range flows {
		f := &flows[i]
		reason := breachReason(*f, pol, lanNet, gw, guest, tcpOK, udpOK)
		if reason == "" {
			continue
		}
		f.PolicyBreach = true
		f.PolicyReason = reason
	}
}

func portSet(ports []int) map[int]bool {
	m := map[int]bool{}
	for _, p := range ports {
		m[p] = true
	}
	return m
}

func isLabIP(ip net.IP, lanNet *net.IPNet, gw, guest net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip.IsPrivate() {
		if lanNet != nil && lanNet.Contains(ip) {
			return true
		}
		// Other RFC1918 is blocked at nftables; still not "WAN allowlist" traffic.
		return true
	}
	if gw != nil && ip.Equal(gw) {
		return true
	}
	if guest != nil && ip.Equal(guest) {
		return true
	}
	return false
}

func breachReason(f Flow, pol config.PermissivePolicy, lanNet *net.IPNet, gw, guest net.IP, tcpOK, udpOK map[int]bool) string {
	dst := net.ParseIP(f.DstIP)
	src := net.ParseIP(f.SrcIP)
	if dst == nil {
		return ""
	}
	tr := strings.ToLower(strings.TrimSpace(f.Transport))
	proto := strings.ToUpper(strings.TrimSpace(f.Protocol))
	if proto == "ARP" || proto == "IGMP" || proto == "DHCP" || tr == "arp" {
		return ""
	}
	if isLabIP(dst, lanNet, gw, guest) {
		return ""
	}
	// Inbound to guest from WAN is not a guest-originated breach.
	if guest != nil && dst.Equal(guest) {
		return ""
	}
	if src != nil && isLabIP(src, lanNet, gw, guest) {
		// guest/lab → public
	} else if src != nil && !src.IsPrivate() && guest != nil && dst.Equal(guest) {
		return ""
	}

	if tr == "icmp" || proto == "ICMP" || proto == "ICMPV6" {
		if pol.ICMP() {
			return ""
		}
		return "ICMP to WAN not allowed by permissive policy"
	}

	port := f.DstPort
	if pol.ForceDNS() && (port == 53 || port == 853) && (tr == "udp" || tr == "tcp" || proto == "DNS") {
		if gw != nil && dst.Equal(gw) {
			return ""
		}
		return fmt.Sprintf("DNS/DoT to %s:%d bypassed gateway", f.DstIP, port)
	}

	if tr == "tcp" {
		if tcpOK[port] {
			return ""
		}
		return fmt.Sprintf("TCP/%d to WAN not in permissive allowlist", port)
	}
	if tr == "udp" {
		if udpOK[port] {
			return ""
		}
		return fmt.Sprintf("UDP/%d to WAN not in permissive allowlist", port)
	}
	return fmt.Sprintf("%s to WAN not in permissive allowlist", firstNonEmpty(proto, tr, "traffic"))
}
