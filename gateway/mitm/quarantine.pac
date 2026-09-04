function FindProxyForURL(url, host) {
    // Explicit fallback PAC — gateway LAN address
    var p = "PROXY __GATEWAY__:8080";
    if (isPlainHostName(host)) return p;
    return p;
}
