#!/usr/bin/env python3
"""Convert mitmproxy hardcopy (.mitm) to flows.jsonl for evidence UI."""
from __future__ import annotations

import argparse
import base64
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

MAX_BODY = 65536


def _is_ip(host: str) -> bool:
    h = (host or "").strip().strip("[]")
    if not h:
        return False
    if h.count(".") == 3 and all(p.isdigit() for p in h.split(".")):
        return True
    return ":" in h and "/" not in h and " " not in h


def _host_from_url(url: str) -> str:
    try:
        from urllib.parse import urlparse

        h = urlparse(url).hostname or ""
        return h.strip("[]")
    except Exception:
        return ""


def _display_host(flow, url: str) -> str:
    from_url = _host_from_url(url)
    raw = str(getattr(flow.request, "host", "") or "").strip()
    if from_url and not _is_ip(from_url):
        return from_url
    if raw and not _is_ip(raw):
        return raw
    return from_url or raw


def _ts(flow) -> str:
    try:
        t = flow.request.timestamp_start
        if t:
            return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        pass
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _body_preview(msg, limit: int = MAX_BODY) -> dict:
    raw = msg.raw_content or b""
    n = len(raw)
    truncated = n > limit
    chunk = raw[:limit]
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


def _headers(msg) -> dict:
    try:
        return {str(k): str(v) for k, v in msg.headers.items(multi=True)}
    except Exception:
        return {str(k): str(v) for k, v in dict(msg.headers).items()}


def flow_to_record(flow, max_body: int = MAX_BODY) -> dict | None:
    from mitmproxy import http

    if not isinstance(flow, http.HTTPFlow):
        return None
    url = flow.request.pretty_url
    if "quarantine.pac" in url or "mitmproxy-ca-cert" in url or url.rstrip("/").endswith("/cert.cer"):
        return None
    resolved = []
    sc = getattr(flow, "server_conn", None)
    if sc is not None:
        peer = getattr(sc, "peername", None)
        if peer and len(peer) >= 1 and peer[0]:
            resolved.append(str(peer[0]))
        ip_addr = getattr(sc, "ip_address", None)
        if ip_addr:
            try:
                host = ip_addr[0] if isinstance(ip_addr, (list, tuple)) else str(ip_addr)
                if host and host not in resolved:
                    resolved.append(str(host))
            except Exception:
                pass
    rec = {
        "t": _ts(flow),
        "method": flow.request.method,
        "url": url,
        "host": _display_host(flow, url),
        "path": flow.request.path,
        "resolvedIps": resolved,
        "request": {
            "headers": _headers(flow.request),
            **_body_preview(flow.request, max_body),
        },
    }
    if flow.response is not None:
        rec["status"] = flow.response.status_code
        rec["reason"] = flow.response.reason
        rec["response"] = {
            "headers": _headers(flow.response),
            **_body_preview(flow.response, max_body),
        }
    else:
        rec["status"] = None
        rec["response"] = None
    return rec


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mitm_path")
    ap.add_argument("jsonl_path")
    ap.add_argument("--max-body", type=int, default=MAX_BODY)
    args = ap.parse_args()

    src = Path(args.mitm_path)
    dst = Path(args.jsonl_path)
    if not src.is_file() or src.stat().st_size == 0:
        dst.write_text("", encoding="utf-8")
        return 0

    from mitmproxy import io

    count = 0
    with src.open("rb") as fh, dst.open("w", encoding="utf-8") as out:
        reader = io.FlowReader(fh)
        for flow in reader.stream():
            rec = flow_to_record(flow, args.max_body)
            if not rec:
                continue
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            count += 1
    print(f"exported {count} flows -> {dst}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
