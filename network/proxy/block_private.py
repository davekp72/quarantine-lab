"""mitmproxy addon: block private/link-local destinations (legacy host proxy path)."""
import ipaddress
import os
import socket
from datetime import datetime
from mitmproxy import ctx, http

PRIVATE_NETS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

PRIVATE_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata",
}

ACCESS_LOG = None
ERROR_LOG = None
PAC_BODY = None
CA_BODY = None
DNS_TIMEOUT_SEC = 2.0


def _is_private_ip(ip: str) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip.strip("[]"))
    except ValueError:
        return False
    return any(addr in net for net in PRIVATE_NETS)


def _is_private(host: str) -> bool:
    if not host:
        return False
    h = host.strip("[]").lower().rstrip(".")
    if h in PRIVATE_HOSTNAMES or h.endswith(".localhost") or h.endswith(".local"):
        return True
    return _is_private_ip(h)


def _dns_resolves_private(host: str) -> bool:
    if not host or _is_private_ip(host.strip("[]")):
        return _is_private(host)
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(DNS_TIMEOUT_SEC)
        try:
            infos = socket.getaddrinfo(host, None)
        finally:
            socket.setdefaulttimeout(old)
        return any(_is_private_ip(str(info[4][0])) for info in infos)
    except OSError:
        return False


def _serve_pac(flow: http.HTTPFlow) -> bool:
    if not PAC_BODY:
        return False
    path = flow.request.path.split("?", 1)[0]
    if path.rstrip("/").endswith("quarantine.pac"):
        flow.response = http.Response.make(
            200,
            PAC_BODY.encode("utf-8"),
            {"Content-Type": "application/x-ns-proxy-autoconfig"},
        )
        return True
    return False


def _serve_ca(flow: http.HTTPFlow) -> bool:
    if not CA_BODY:
        return False
    path = flow.request.path.split("?", 1)[0].rstrip("/").lower()
    if path.endswith("mitmproxy-ca-cert.cer") or path.endswith("/cert.cer"):
        flow.response = http.Response.make(
            200,
            CA_BODY,
            {"Content-Type": "application/x-x509-ca-cert"},
        )
        return True
    return False


class QuarantineBlocker:
    def request(self, flow: http.HTTPFlow) -> None:
        if _serve_pac(flow) or _serve_ca(flow):
            return

        host = flow.request.host
        ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        line = f"{ts} {flow.request.method} {flow.request.pretty_url}\n"
        if ACCESS_LOG:
            ACCESS_LOG.write(line)
            ACCESS_LOG.flush()
        if _is_private(host) or _dns_resolves_private(host):
            msg = f"blocked private destination: {host} url={flow.request.pretty_url}"
            ctx.log.warn(msg)
            if ERROR_LOG:
                ERROR_LOG.write(msg + "\n")
                ERROR_LOG.flush()
            flow.response = http.Response.make(
                403,
                b"Quarantine proxy: private network destinations are blocked.",
                {"Content-Type": "text/plain"},
            )


addons = [QuarantineBlocker()]


def load(loader):
    global ACCESS_LOG, ERROR_LOG, PAC_BODY, CA_BODY, DNS_TIMEOUT_SEC
    access = os.environ.get("QUARANTINE_ACCESS_LOG", "")
    errors = os.environ.get("QUARANTINE_ERROR_LOG", "")
    pac_path = os.environ.get("QUARANTINE_PAC_PATH", "")
    ca_path = os.environ.get("QUARANTINE_CA_PATH", "")
    try:
        DNS_TIMEOUT_SEC = float(os.environ.get("QUARANTINE_DNS_TIMEOUT_SEC", str(DNS_TIMEOUT_SEC)))
    except ValueError:
        pass
    if access:
        parent = os.path.dirname(access)
        if parent:
            os.makedirs(parent, exist_ok=True)
        ACCESS_LOG = open(access, "a", encoding="utf-8")
    if errors:
        parent = os.path.dirname(errors)
        if parent:
            os.makedirs(parent, exist_ok=True)
        ERROR_LOG = open(errors, "a", encoding="utf-8")
    if pac_path and os.path.isfile(pac_path):
        with open(pac_path, "r", encoding="utf-8") as pac_file:
            PAC_BODY = pac_file.read()
    if ca_path and os.path.isfile(ca_path):
        with open(ca_path, "rb") as ca_file:
            CA_BODY = ca_file.read()


def done():
    global ACCESS_LOG, ERROR_LOG
    for handle in (ACCESS_LOG, ERROR_LOG):
        if handle:
            handle.close()
    ACCESS_LOG = ERROR_LOG = None
