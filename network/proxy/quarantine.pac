function FindProxyForURL(url, host) {
    if (isPlainHostName(host)) return "PROXY 10.0.2.2:8080";
    if (shExpMatch(host, "10.*")) return "PROXY 10.0.2.2:8080";
    if (shExpMatch(host, "172.16.*") || shExpMatch(host, "172.17.*") ||
        shExpMatch(host, "172.18.*") || shExpMatch(host, "172.19.*") ||
        shExpMatch(host, "172.2*.*") || shExpMatch(host, "172.30.*") ||
        shExpMatch(host, "172.31.*")) return "PROXY 10.0.2.2:8080";
    if (shExpMatch(host, "192.168.*")) return "PROXY 10.0.2.2:8080";
    if (shExpMatch(host, "169.254.*")) return "PROXY 10.0.2.2:8080";
    return "PROXY 10.0.2.2:8080";
}
