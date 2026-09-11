#!/usr/bin/env python3
"""Inject permissive nftables snippets into a rendered ruleset template."""
import pathlib
import sys


def inject(text, marker, body):
    if body and not body.endswith("\n"):
        body = body + "\n"
    text = text.replace(marker + "\n", body)
    return text.replace(marker, body)


def main():
    if len(sys.argv) < 2:
        print("usage: nft-inject-permissive.py RENDERED [forward.inc] [nat.inc] [output.inc]", file=sys.stderr)
        return 2
    path = pathlib.Path(sys.argv[1])
    forward = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2] else None
    nat = pathlib.Path(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] else None
    output = pathlib.Path(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[4] else None

    def read(p):
        if p is not None and p.is_file():
            return p.read_text()
        return ""

    t = path.read_text()
    t = inject(t, "__PERMISSIVE_WAN_RULES__", read(forward))
    t = inject(t, "__PERMISSIVE_DNS_NAT__", read(nat))
    out_body = read(output)
    if not out_body:
        # Safe default so permissive mode never leaves a placeholder.
        out_body = "    tcp dport { 80, 443 } accept\n"
    t = inject(t, "__PERMISSIVE_OUTPUT_RULES__", out_body)
    path.write_text(t)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
