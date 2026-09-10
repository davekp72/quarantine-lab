#!/usr/bin/env python3
"""Verify FakeNet explicit-proxy HTTP GET and HTTPS CONNECT (browser path)."""
from __future__ import annotations

import datetime
import socket
import ssl
import sys

from cryptography import x509

LAN = sys.argv[1] if len(sys.argv) > 1 else "10.66.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080


def _read_http(sock: socket.socket, limit: int = 65536) -> bytes:
    data = b""
    sock.settimeout(12)
    while len(data) < limit:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if b"\r\n\r\n" in data and (
            b"Content-Length:" not in data.split(b"\r\n\r\n", 1)[0]
            or len(data.split(b"\r\n\r\n", 1)[-1]) > 0
        ):
            # Stop once headers + some body arrived; FakeNet pages are small.
            if b"\r\n\r\n" in data and len(data) > 64:
                break
    return data


def test_http_proxy() -> None:
    s = socket.create_connection((LAN, PORT), 8)
    try:
        s.sendall(
            b"GET http://example.test/ HTTP/1.1\r\n"
            b"Host: example.test\r\n"
            b"Connection: close\r\n\r\n"
        )
        resp = _read_http(s)
    finally:
        s.close()
    if not resp.startswith(b"HTTP/1."):
        raise SystemExit("HTTP proxy: not HTTP (%r)" % resp[:80])
    code = resp.split(b" ", 2)[1]
    if code not in (b"200", b"301", b"302"):
        raise SystemExit("HTTP proxy: status %s body=%r" % (code, resp[:200]))
    print("proxy-http-ok", code.decode())


def test_https_connect() -> None:
    s = socket.create_connection((LAN, PORT), 8)
    try:
        s.sendall(
            b"CONNECT yellow.com:443 HTTP/1.1\r\n"
            b"Host: yellow.com:443\r\n"
            b"Proxy-Connection: keep-alive\r\n\r\n"
        )
        hdr = b""
        s.settimeout(8)
        while b"\r\n\r\n" not in hdr:
            chunk = s.recv(1)
            if not chunk:
                break
            hdr += chunk
            if len(hdr) > 4096:
                break
        first = hdr.split(b"\r\n", 1)[0]
        print("connect-resp", first.decode("latin-1", "replace"))
        if b" 200 " not in first and not first.endswith(b" 200"):
            raise SystemExit("CONNECT failed: %r" % hdr[:300])
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_alpn_protocols(["http/1.1"])
        except Exception:
            pass
        ss = ctx.wrap_socket(s, server_hostname="yellow.com")
        print("tls", ss.version(), "alpn", ss.selected_alpn_protocol())
        der = ss.getpeercert(binary_form=True)
        if not der:
            raise SystemExit("HTTPS after CONNECT: no peer certificate")
        cert = x509.load_der_x509_certificate(der)
        nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(
            tzinfo=datetime.timezone.utc
        )
        na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(
            tzinfo=datetime.timezone.utc
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        print("leaf-nb", nb.isoformat(), "leaf-na", na.isoformat())
        if nb > now - datetime.timedelta(hours=12):
            raise SystemExit(
                "leaf notBefore %s is too close to gateway now; Chrome ERR_CERT_DATE_INVALID "
                "when the Windows guest clock lags" % nb.isoformat()
            )
        if (na - nb) > datetime.timedelta(days=398):
            raise SystemExit("leaf lifetime %s exceeds Chrome 398-day limit" % (na - nb))
        ss.sendall(
            b"GET / HTTP/1.1\r\n"
            b"Host: yellow.com\r\n"
            b"Connection: close\r\n\r\n"
        )
        body = _read_http(ss)
        ss.close()
    except Exception:
        try:
            s.close()
        except OSError:
            pass
        raise
    if not body.startswith(b"HTTP/1."):
        raise SystemExit("HTTPS after CONNECT: not HTTP (%r)" % body[:120])
    code = body.split(b" ", 2)[1]
    if code != b"200":
        raise SystemExit("HTTPS after CONNECT: status %s body=%r" % (code, body[:200]))
    print("proxy-https-connect-ok", code.decode(), "len", len(body))


if __name__ == "__main__":
    test_http_proxy()
    test_https_connect()
    print("browser-proxy-path-ok")
