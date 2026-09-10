#!/usr/bin/env python3
"""Install the quarantine HTTPListener (CONNECT+TLS) over FakeNet's copy.

Regex patches against FakeNet's file were skipped when the UseSSL block did not
match, so CONNECT never landed and browsers got HTTP/1.0 501.
"""
from __future__ import annotations

import pathlib
import shutil
import sys

MARKER = "QUARANTINE_CONNECT_PATCH_V3"


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: patch_httplistener.py DEST [SRC]", file=sys.stderr)
        return 2
    dest = pathlib.Path(sys.argv[1])
    if len(sys.argv) >= 3:
        src = pathlib.Path(sys.argv[2])
    else:
        src = pathlib.Path(__file__).resolve().parent / "HTTPListener.py"
    if not src.is_file():
        print("missing source HTTPListener.py: %s" % src, file=sys.stderr)
        return 1
    text = src.read_text(encoding="utf-8")
    if MARKER not in text or "def do_CONNECT" not in text:
        print("source HTTPListener.py is not the CONNECT-capable copy: %s" % src, file=sys.stderr)
        return 1
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dest)
    print("installed %s -> %s" % (src, dest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
