#!/usr/bin/env python3
"""Extract the SOME/IP identity the tester must assert from the DUT's own
vsomeip.json — the single home of these values, since the DUT advertises exactly
what that file declares.

smoke-test.sh sources the output to build its `--expect` surface, deriving the
identity at runtime instead of re-stating it as bash literals. The Rust
orchestrator parses the same file via config.rs `parse_dut_identity`; keeping
both drivers derived from the one file means they can never disagree and neither
can drift from what the DUT actually serves. The field mapping here MUST stay in
lockstep with that Rust parser.

Usage:
  tools/dut_identity.py <path-to-vsomeip.json>

Prints `key=value` lines (one per identity key) on stdout. Exits non-zero with a
diagnostic on stderr if the file or any required field is missing — never emit a
partial surface that would let an identity case silently pass against an absent
expectation.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def _require(node, key: str, where: str):
    """Fetch a string scalar at node[key], or fail loud naming the JSON path."""
    if not isinstance(node, dict) or key not in node:
        sys.exit(f"dut_identity: vsomeip.json: {where}.{key} missing")
    val = node[key]
    if not isinstance(val, str):
        sys.exit(f"dut_identity: vsomeip.json: {where}.{key} is not a string: {val!r}")
    return val


def extract(cfg_path: Path) -> dict[str, str]:
    try:
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        sys.exit(f"dut_identity: vsomeip.json not found: {cfg_path}")
    except json.JSONDecodeError as exc:
        sys.exit(f"dut_identity: vsomeip.json parse error at {cfg_path}: {exc}")

    services = data.get("services")
    if not isinstance(services, list) or not services:
        sys.exit("dut_identity: vsomeip.json: services[0] missing")
    svc = services[0]
    reliable = svc.get("reliable") if isinstance(svc, dict) else None
    if not isinstance(reliable, dict):
        sys.exit("dut_identity: vsomeip.json: services[0].reliable missing")
    sd = data.get("service-discovery")
    if not isinstance(sd, dict):
        sys.exit("dut_identity: vsomeip.json: service-discovery block missing")

    # The threshold/multicast eventgroup (0x0008 for tc8-dut) carries the
    # notification multicast endpoint; pick whichever eventgroup declares one
    # (mirrors the orchestrator's find_map over eventgroups[*].multicast).
    # The source file MUST be the base/full vsomeip.json: the multi-service/
    # instance variants are spawn-only and omit this eventgroup, so deriving the
    # identity surface from one would fail loud here (correct — they are not the
    # expectation source; smoke-test.sh feeds the base VSOMEIP_CFG to derive it).
    mcast = None
    egs = svc.get("eventgroups")
    if isinstance(egs, list):
        for eg in egs:
            if isinstance(eg, dict) and isinstance(eg.get("multicast"), dict):
                mcast = eg["multicast"]
                break
    if mcast is None:
        sys.exit("dut_identity: vsomeip.json: no eventgroup with a multicast endpoint")

    return {
        "service_id": _require(svc, "service", "services[0]"),
        "instance_id": _require(svc, "instance", "services[0]"),
        "udp_port": _require(svc, "unreliable", "services[0]"),
        "tcp_port": _require(reliable, "port", "services[0].reliable"),
        "sd_multicast_ip": _require(sd, "multicast", "service-discovery"),
        "ttl": _require(sd, "ttl", "service-discovery"),
        "mcast_ipv4": _require(mcast, "address", "services[0].eventgroups[*].multicast"),
        "mcast_port": _require(mcast, "port", "services[0].eventgroups[*].multicast"),
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.exit("usage: dut_identity.py <path-to-vsomeip.json>")
    identity = extract(Path(argv[1]))
    for key, value in identity.items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
