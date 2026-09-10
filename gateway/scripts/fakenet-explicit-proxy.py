#!/usr/bin/env python3
"""FakeNet-mode explicit proxy for the Windows guest.

The lab guest is configured with WinINET PAC + ProxyServer 10.66.0.1:8080
(permissive MITM). Chrome uses HTTP CONNECT to that port. FakeNet stops
mitmproxy, so CONNECT used to fail with ERR_TUNNEL_CONNECTION_FAILED
while curl (direct to :443) worked.

This process:
  - Serves PAC / CA / CRL over HTTP
  - Answers CONNECT by splicing to FakeNet HTTPS (:443)
  - Forwards absolute-form HTTP proxy GETs to FakeNet :80
"""
from __future__ import annotations

import os
import select
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

LAN_IP = os.environ.get("QUARANTINE_LAN_IP", "10.66.0.1")
WWW = os.environ.get("QUARANTINE_FAKENET_WWW", "/var/log/quarantine/fakenet/www")
HTTPS_PORT = int(os.environ.get("QUARANTINE_FAKENET_HTTPS_PORT", "443"))
HTTP_PORT = int(os.environ.get("QUARANTINE_FAKENET_HTTP_PORT", "80"))
LISTEN_PORTS = [
    int(p) for p in os.environ.get("QUARANTINE_FAKENET_PROXY_PORTS", "8080,8081").split(",") if p.strip()
]


def _connect_backend(port: int) -> socket.socket:
    last: OSError | None = None
    for host in (LAN_IP, "127.0.0.1"):
        try:
            return socket.create_connection((host, port), timeout=10)
        except OSError as exc:
            last = exc
    if last is not None:
        raise last
    raise OSError("no FakeNet backend for port %s" % port)


def _relay(a: socket.socket, b: socket.socket, idle: float = 120.0) -> None:
    sockets = [a, b]
    try:
        while True:
            r, _, _ = select.select(sockets, [], [], idle)
            if not r:
                break
            for src in r:
                dst = b if src is a else a
                try:
                    data = src.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                try:
                    dst.sendall(data)
                except OSError:
                    return
    finally:
        for s in sockets:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass


def _pac_body() -> bytes:
    pac = (
        "function FindProxyForURL(url, host) {\n"
        f'    return "PROXY {LAN_IP}:8080";\n'
        "}\n"
    )
    path = os.path.join(WWW, "quarantine.pac")
    try:
        with open(path, "rb") as f:
            data = f.read()
        if data.strip():
            return data
    except OSError:
        pass
    return pac.encode("ascii")


def _www_file(name: str) -> tuple[bytes, str] | None:
    path = os.path.join(WWW, name)
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as f:
        data = f.read()
    lower = name.lower()
    if lower.endswith(".pac"):
        ctype = "application/x-ns-proxy-autoconfig"
    elif lower.endswith(".cer"):
        ctype = "application/x-x509-ca-cert"
    elif lower.endswith(".crl"):
        ctype = "application/pkix-crl"
    elif lower.endswith(".pem"):
        ctype = "application/x-pem-file"
    else:
        ctype = "application/octet-stream"
    return data, ctype


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 30

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def do_CONNECT(self) -> None:
        try:
            backend = _connect_backend(HTTPS_PORT)
        except OSError as exc:
            self.send_error(502, "FakeNet HTTPS not reachable: %s" % exc)
            return
        self.send_response(200, "Connection Established")
        self.send_header("Proxy-Agent", "quarantine-fakenet-proxy")
        self.end_headers()
        try:
            self.wfile.flush()
        except OSError:
            pass
        self.close_connection = True
        _relay(self.connection, backend)

    def do_GET(self) -> None:
        self._handle_http()

    def do_HEAD(self) -> None:
        self._handle_http(body=False)

    def do_POST(self) -> None:
        self._handle_http()

    def do_PUT(self) -> None:
        self._handle_http()

    def do_DELETE(self) -> None:
        self._handle_http()

    def _local_path(self) -> str:
        parsed = urlparse(self.path)
        if parsed.scheme in ("http", "https"):
            path = parsed.path or "/"
        else:
            path = parsed.path or self.path
        return path.split("?", 1)[0]

    def _handle_http(self, body: bool = True) -> None:
        path = self._local_path().rstrip("/").lower()
        mapping = {
            "/quarantine.pac": ("quarantine.pac", None),
            "/mitmproxy-ca-cert.cer": ("mitmproxy-ca-cert.cer", None),
            "/cert.cer": ("mitmproxy-ca-cert.cer", None),
            "/mitmproxy-ca-cert.pem": ("mitmproxy-ca-cert.pem", None),
            "/mitmproxy-ca.crl": ("mitmproxy-ca.crl", None),
            "/ca.crl": ("mitmproxy-ca.crl", None),
        }
        if path in mapping or path == "/quarantine.pac":
            if path == "/quarantine.pac" or path.endswith("quarantine.pac"):
                data = _pac_body()
                self._send_bytes(200, data, "application/x-ns-proxy-autoconfig", body=body)
                return
            name = mapping.get(path, (None, None))[0]
            if name:
                got = _www_file(name)
                if got:
                    data, ctype = got
                    self._send_bytes(200, data, ctype, body=body)
                    return
        self._forward_to_fakenet_http(body=body)

    def _send_bytes(self, code: int, data: bytes, ctype: str, body: bool = True) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(data)

    def _forward_to_fakenet_http(self, body: bool = True) -> None:
        parsed = urlparse(self.path)
        if parsed.scheme in ("http", "https"):
            origin = parsed.path or "/"
            if parsed.query:
                origin += "?" + parsed.query
        else:
            origin = self.path
        try:
            backend = _connect_backend(HTTP_PORT)
        except OSError as exc:
            self.send_error(502, "FakeNet HTTP not reachable: %s" % exc)
            return
        hdrs = []
        for k, v in self.headers.items():
            if k.lower() in ("proxy-connection", "proxy-authorization"):
                continue
            hdrs.append("%s: %s" % (k, v))
        length = int(self.headers.get("Content-Length") or 0)
        extra = self.rfile.read(length) if length > 0 else b""
        req = "%s %s HTTP/1.1\r\n%s\r\n\r\n" % (self.command, origin, "\r\n".join(hdrs))
        try:
            backend.sendall(req.encode("latin-1") + extra)
            if not body or self.command == "HEAD":
                backend.settimeout(15)
                data = b""
                while True:
                    chunk = backend.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                    if b"\r\n\r\n" in data:
                        break
                self.connection.sendall(data)
                backend.close()
                return
            self.close_connection = True
            _relay(self.connection, backend)
        except OSError:
            try:
                backend.close()
            except OSError:
                pass


def main() -> int:
    os.makedirs(WWW, exist_ok=True)
    pac_path = os.path.join(WWW, "quarantine.pac")
    if not os.path.isfile(pac_path):
        with open(pac_path, "wb") as f:
            f.write(_pac_body())
    threads = []
    servers = []
    for port in LISTEN_PORTS:
        httpd = ThreadingHTTPServer(("0.0.0.0", port), Handler)
        httpd.daemon_threads = True
        servers.append(httpd)
        t = threading.Thread(target=httpd.serve_forever, name="proxy-%d" % port, daemon=True)
        t.start()
        threads.append(t)
        sys.stderr.write("fakenet-explicit-proxy listening on 0.0.0.0:%d (CONNECT -> %s:%d)\n" % (port, LAN_IP, HTTPS_PORT))
    try:
        threads[0].join()
    except KeyboardInterrupt:
        pass
    for httpd in servers:
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
