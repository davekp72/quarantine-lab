#!/usr/bin/env python3
"""Allow FakeNet Linux diverter under CAP_NET_ADMIN (non-root systemd).

Upstream check_privileged() only accepts uid 0. Lab runs FakeNet as
quarantine-fakenet with AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CAP_NET_BIND_SERVICE — treat effective CAP_NET_ADMIN as privileged.
"""
from __future__ import annotations

import pathlib
import re
import sys

NEW = '''    def check_privileged(self):
        """Return True if we can drive netfilter (root or CAP_NET_ADMIN)."""
        import os
        if os.name == 'nt':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        if os.getuid() == 0:
            return True
        # CAP_NET_ADMIN == 12; AmbientCapabilities put it in CapEff.
        try:
            with open('/proc/self/status', 'r', encoding='utf-8') as status:
                for line in status:
                    if line.startswith('CapEff:'):
                        cap = int(line.split()[1], 16)
                        return bool(cap & (1 << 12))
        except Exception:
            pass
        return False
'''


def patch(path: pathlib.Path) -> bool:
    text = path.read_text(encoding="utf-8")
    if "CapEff:" in text and "1 << 12" in text:
        print("diverter-privcheck already patched:", path)
        return False
    # Match the method body through the return (non-greedy until next top-level def at same indent).
    pat = re.compile(
        r"    def check_privileged\(self\):.*?(?=\n    def |\nclass |\Z)",
        re.DOTALL,
    )
    if not pat.search(text):
        raise SystemExit(f"check_privileged not found in {path}")
    new_text = pat.sub(NEW.rstrip() + "\n\n", text, count=1)
    if new_text == text:
        raise SystemExit(f"patch produced no change for {path}")
    path.write_text(new_text, encoding="utf-8")
    print("patched diverter-privcheck:", path)
    return True


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} /path/to/diverterbase.py")
    patch(pathlib.Path(sys.argv[1]))


if __name__ == "__main__":
    main()
