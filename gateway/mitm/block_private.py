"""mitmproxy addon: block private/link-local destinations, serve PAC, log access + flow bodies."""
import base64
import ipaddress
import json
import os
import socket
from datetime import datetime, timezone
from mitmproxy import ctx, http

PRIVATE_NETS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
]

PRIVATE_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
    "metadata",
}

ACCESS_LOG = None
ERROR_LOG = None
FLOW_LOG = None
PAC_BODY = None
CA_BODY = None
MAX_BODY = 65536
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
    if _is_private_ip(h):
        return True
    return False


def _dns_resolves_private(host: str) -> tuple[bool, list[str]]:
    """Resolve host and report whether any answer is private/reserved."""
    if not host or _is_private_ip(host.strip("[]")):
        return _is_private(host), []
    ips: list[str] = []
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(DNS_TIMEOUT_SEC)
        try:
            infos = socket.getaddrinfo(host, None)
        finally:
            socket.setdefaulttimeout(old)
        for info in infos:
            ip = str(info[4][0])
            if ip and ip not in ips:
                ips.append(ip)
    except OSError:
        return False, ips
    return any(_is_private_ip(ip) for ip in ips), ips


def _block(flow: http.HTTPFlow, reason: str) -> None:
    ctx.log.warn(reason)
    if ERROR_LOG:
        ERROR_LOG.write(reason + "\n")
        ERROR_LOG.flush()
    flow.response = http.Response.make(
        403,
        b"Quarantine proxy: private network destinations are blocked.",
        {"Content-Type": "text/plain"},
    )


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


def _is_noise_url(url: str) -> bool:
    lower = (url or "").lower()
    return (
        "quarantine.pac" in lower
        or "mitmproxy-ca-cert" in lower
        or lower.rstrip("/").endswith("/cert.cer")
    )


def _headers(msg) -> dict:
    try:
        return {str(k): str(v) for k, v in msg.headers.items(multi=True)}
    except Exception:
        return {str(k): str(v) for k, v in dict(msg.headers).items()}


def _body_preview(msg) -> dict:
    raw = msg.raw_content or b""
    n = len(raw)
    truncated = n > MAX_BODY
    chunk = raw[:MAX_BODY]
    ctype = (msg.headers.get("content-type") or "").lower()
    out = {
        "contentType": msg.headers.get("content-type", ""),
        "bodyBytes": n,
        "bodyTruncated": truncated,
        "encoding": "utf-8",
        "body": "",
    }
    if not chunk:
        return out
    textish = any(
        x in ctype
        for x in (
            "text/",
            "json",
            "xml",
            "javascript",
            "x-www-form-urlencoded",
            "html",
            "csv",
            "svg",
        )
    ) or not ctype
    if textish:
        try:
            out["body"] = chunk.decode("utf-8")
            return out
        except UnicodeDecodeError:
            try:
                out["body"] = chunk.decode("latin-1")
                out["encoding"] = "latin-1"
                return out
            except Exception:
                pass
    out["encoding"] = "base64"
    out["body"] = base64.b64encode(chunk).decode("ascii")
    return out


def _server_ips(flow: http.HTTPFlow) -> list:
    """Upstream IPs the proxy actually connected to (name resolution result)."""
    ips = []
    sc = getattr(flow, "server_conn", None)
    if not sc:
        return ips
    peer = getattr(sc, "peername", None)
    if peer and len(peer) >= 1 and peer[0]:
        ips.append(str(peer[0]))
    ip_addr = getattr(sc, "ip_address", None)
    if ip_addr:
        try:
            host = ip_addr[0] if isinstance(ip_addr, (list, tuple)) else str(ip_addr)
            if host and host not in ips:
                ips.append(str(host))
        except Exception:
            pass
    return ips


def _is_ip_host(host: str) -> bool:
    h = (host or "").strip().strip("[]")
    if not h:
        return False
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def _host_from_url(url: str) -> str:
    try:
        from urllib.parse import urlparse

        return (urlparse(url).hostname or "").strip("[]")
    except Exception:
        return ""


def _display_host(flow: http.HTTPFlow, url: str) -> str:
    from_url = _host_from_url(url)
    raw = str(getattr(flow.request, "host", "") or "").strip()
    if from_url and not _is_ip_host(from_url):
        return from_url
    if raw and not _is_ip_host(raw):
        return raw
    return from_url or raw


def _write_flow(flow: http.HTTPFlow) -> None:
    if not FLOW_LOG:
        return
    url = flow.request.pretty_url
    if _is_noise_url(url):
        return
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        if flow.request.timestamp_start:
            ts = datetime.fromtimestamp(flow.request.timestamp_start, tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
    except Exception:
        pass
    resolved = _server_ips(flow)
    rec = {
        "t": ts,
        "method": flow.request.method,
        "url": url,
        "host": _display_host(flow, url),
        "path": flow.request.path,
        "resolvedIps": resolved,
        "request": {
            "headers": _headers(flow.request),
            **_body_preview(flow.request),
        },
    }
    if flow.response is not None:
        rec["status"] = flow.response.status_code
        rec["reason"] = getattr(flow.response, "reason", "") or ""
        rec["response"] = {
            "headers": _headers(flow.response),
            **_body_preview(flow.response),
        }
    else:
        rec["status"] = None
        rec["response"] = None
    FLOW_LOG.write(json.dumps(rec, ensure_ascii=False) + "\n")
    FLOW_LOG.flush()


class QuarantineBlocker:
    def request(self, flow: http.HTTPFlow) -> None:
        if _serve_pac(flow) or _serve_ca(flow):
            return

        host = flow.request.host
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        line = f"{ts} {flow.request.method} {flow.request.pretty_url}\n"
        if ACCESS_LOG:
            ACCESS_LOG.write(line)
            ACCESS_LOG.flush()
        if _is_private(host):
            _block(flow, f"blocked private destination: {host} url={flow.request.pretty_url}")
            return
        private_dns, ips = _dns_resolves_private(host)
        if private_dns:
            _block(
                flow,
                f"blocked private DNS answer: {host} -> {','.join(ips)} url={flow.request.pretty_url}",
            )

    def response(self, flow: http.HTTPFlow) -> None:
        # Defense in depth: if upstream somehow connected to a private IP, redact.
        for ip in _server_ips(flow):
            if _is_private_ip(ip):
                msg = f"blocked private upstream IP after connect: {ip} url={flow.request.pretty_url}"
                ctx.log.warn(msg)
                if ERROR_LOG:
                    ERROR_LOG.write(msg + "\n")
                    ERROR_LOG.flush()
                flow.response = http.Response.make(
                    403,
                    b"Quarantine proxy: private network destinations are blocked.",
                    {"Content-Type": "text/plain"},
                )
                break
        _write_flow(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            _write_flow(flow)


addons = [QuarantineBlocker()]


def load(loader):
    global ACCESS_LOG, ERROR_LOG, FLOW_LOG, PAC_BODY, CA_BODY, MAX_BODY, DNS_TIMEOUT_SEC
    access = os.environ.get("QUARANTINE_ACCESS_LOG", "")
    errors = os.environ.get("QUARANTINE_ERROR_LOG", "")
    flows = os.environ.get("QUARANTINE_FLOWS_JSONL", "")
    pac_path = os.environ.get("QUARANTINE_PAC_PATH", "")
    ca_path = os.environ.get("QUARANTINE_CA_PATH", "")
    try:
        MAX_BODY = int(os.environ.get("QUARANTINE_FLOW_BODY_MAX", str(MAX_BODY)))
    except ValueError:
        pass
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
    if flows:
        parent = os.path.dirname(flows)
        if parent:
            os.makedirs(parent, exist_ok=True)
        FLOW_LOG = open(flows, "a", encoding="utf-8")
    if pac_path and os.path.isfile(pac_path):
        with open(pac_path, "r", encoding="utf-8") as pac_file:
            PAC_BODY = pac_file.read()
    if ca_path and os.path.isfile(ca_path):
        with open(ca_path, "rb") as ca_file:
            CA_BODY = ca_file.read()


def done():
    global ACCESS_LOG, ERROR_LOG, FLOW_LOG
    for handle in (ACCESS_LOG, ERROR_LOG, FLOW_LOG):
        if handle:
            handle.close()
    ACCESS_LOG = ERROR_LOG = FLOW_LOG = None
