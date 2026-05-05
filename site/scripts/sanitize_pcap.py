#!/usr/bin/env python3
"""Pre-deploy guard for ``site/src/data/pcap/*.json``.

Fails when a captured packet field looks like real-world infrastructure
data that should not be published from a test environment. Runs in CI as
the first step before the site builds, so leakage is caught before the
artefact is uploaded to GitHub Pages.

Checks:
  - IP fields must be private (RFC 1918), link-local (169.254/16),
    loopback (127/8), multicast, broadcast (255.255.255.255), or
    unspecified (0.0.0.0). Any global/public IP fails the run.
  - MAC fields must satisfy at least one of:
      • Locally-administered (U/L bit set on first octet) — covers the
        02:00:..., 02:42:..., 02:FF:... fixture space the harness uses.
      • Multicast bit set (LLDP, IPv4/IPv6 multicast L2 destinations).
      • Broadcast (ff:ff:ff:ff:ff:ff) or all-zero (00:00:00:00:00:00).
    Anything else implies a real vendor OUI from production hardware.

Run locally before pushing::

    python3 site/scripts/sanitize_pcap.py site/src/data/pcap

Exit 0 on clean, exit 1 on any violation.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from pathlib import Path


LOCAL_BIT = 0x02
MULTICAST_BIT = 0x01

ALLOWED_FIXED_MACS = {
    "ff:ff:ff:ff:ff:ff",  # broadcast
    "00:00:00:00:00:00",  # zero / unset
}


def _is_ok_ip(s: str) -> bool:
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return True  # not parseable; ignored — sanitizer is conservative
    return (
        ip.is_private or ip.is_link_local or ip.is_loopback
        or ip.is_multicast or ip.is_unspecified or ip.is_reserved
        or s == "255.255.255.255"
    )


def _is_ok_mac(s: str) -> bool:
    if not s:
        return True
    s = s.lower()
    if s in ALLOWED_FIXED_MACS:
        return True
    octets = s.split(":")
    if len(octets) != 6:
        return True  # malformed; not our concern
    try:
        first = int(octets[0], 16)
    except ValueError:
        return True
    return bool(first & (LOCAL_BIT | MULTICAST_BIT))


def check_capture(path: Path) -> list[str]:
    issues: list[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"{path}: malformed JSON: {exc}"]

    for key in ("tester_ip", "dut_ip"):
        v = data.get(key)
        if v and not _is_ok_ip(v):
            issues.append(f"{path}: top-level {key}={v!r} is global/public")
    for key in ("tester_mac", "dut_mac"):
        v = data.get(key)
        if v and not _is_ok_mac(v):
            issues.append(f"{path}: top-level {key}={v!r} not in test-fixture space")

    for p in data.get("packets", []):
        idx = p.get("idx", "?")
        for key in ("src_ip", "dst_ip"):
            v = p.get(key)
            if v and not _is_ok_ip(v):
                issues.append(f"{path}: packet[{idx}].{key}={v!r} is global/public")
        for key in ("src_mac", "dst_mac"):
            v = p.get(key)
            if v and not _is_ok_mac(v):
                issues.append(f"{path}: packet[{idx}].{key}={v!r} not in test-fixture space")
    return issues


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("paths", nargs="+",
                    help="Files or directories containing pcap JSON")
    args = ap.parse_args(argv)

    files: list[Path] = []
    for p in args.paths:
        path = Path(p)
        if path.is_dir():
            files.extend(sorted(path.glob("*.json")))
        elif path.exists():
            files.append(path)

    if not files:
        print("OK: no pcap JSON files to scan")
        return 0

    issues: list[str] = []
    for f in files:
        issues.extend(check_capture(f))

    if issues:
        print("Pcap sanitization FAILED:", file=sys.stderr)
        for issue in issues:
            print(f"  - {issue}", file=sys.stderr)
        return 1
    print(f"OK: scanned {len(files)} file(s), no leakage detected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
