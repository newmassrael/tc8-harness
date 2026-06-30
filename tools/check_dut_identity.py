#!/usr/bin/env python3
"""Cross-check that the DUT identity agrees across its three hand-authored sources.

The TC8 v3.0 spec leaves the DUT's <SERVICE-ID>/<INSTANCE>/<PORT>/app-name as
deployment parameters the tester chooses (§5.1.2.3). This project's chosen values
are written, by hand, in three separate artifacts that MUST agree:

  - include/tc8/dut_config.h      the C++ constants the harness/tester compile against
  - dut/dut_service/vsomeip.json  the vsomeip runtime deployment
  - dut/ets/ets.fdepl             the CommonAPI/Franca deployment

A divergence silently breaks every case that depends on the DUT being reachable
under the advertised identity (dut_config.h documents the hand-sync contract). This
is the build-enforced cross-check that contract named as missing: it fails on any
drift between the three sources. There is nothing to GENERATE here — the three are
distinct artifacts with distinct purposes/formats — so this is a pure checker, the
counterpart of the wire-`.def` `--check` gates. Pure-Python (json + re), no deps.

Usage: python3 tools/check_dut_identity.py [--check]   (always checks; exit 1 on drift)
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def parse_dut_config(text):
    out = {}
    for m in re.finditer(
        r"inline constexpr std::uint16_t\s+(k\w+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*;", text
    ):
        out[m.group(1)] = int(m.group(2), 0)
    for m in re.finditer(
        r'inline constexpr const char\*\s+(k\w+)\s*=\s*"([^"]*)"\s*;', text
    ):
        out[m.group(1)] = m.group(2)
    return out


def parse_vsomeip(text):
    d = json.loads(text)
    svc = d["services"][0]
    sd = d["service-discovery"]
    return {
        "app_name": d["applications"][0]["name"],
        "routing": d["routing"],
        "service": int(svc["service"], 0),
        "instance": int(svc["instance"], 0),
        "tcp": int(svc["reliable"]["port"]),
        "udp": int(svc["unreliable"]),
        "sd_mcast": sd["multicast"],
        "sd_port": int(sd["port"]),
    }


def parse_fdepl(text):
    """Parse the interface-level service id and the PRIMARY (ETS / 0x0001) provider
    instance block. ETS2/ETS3 carry their own ids and are not part of the identity
    checked here."""
    svc = re.search(r"SomeIpServiceID\s*=\s*(0x[0-9A-Fa-f]+)", text)
    block = re.search(
        r"instance\s+org\.tc8\.ets\.EnhancedTestability\s*\{(.*?)\}", text, re.DOTALL
    )
    if not svc or not block:
        return None
    b = block.group(1)
    inst = re.search(r"SomeIpInstanceID\s*=\s*(0x[0-9A-Fa-f]+)", b)
    rel = re.search(r"SomeIpReliableUnicastPort\s*=\s*(\d+)", b)
    unrel = re.search(r"SomeIpUnreliableUnicastPort\s*=\s*(\d+)", b)
    if not (inst and rel and unrel):
        return None
    return {
        "service": int(svc.group(1), 0),
        "instance": int(inst.group(1), 0),
        "tcp": int(rel.group(1)),
        "udp": int(unrel.group(1)),
    }


def main():
    cfg = parse_dut_config((ROOT / "include/tc8/dut_config.h").read_text())
    vs = parse_vsomeip((ROOT / "dut/dut_service/vsomeip.json").read_text())
    fd = parse_fdepl((ROOT / "dut/ets/ets.fdepl").read_text())
    if fd is None:
        print(
            "check_dut_identity: could not parse the ETS instance block in "
            "dut/ets/ets.fdepl",
            file=sys.stderr,
        )
        return 1

    # (label, dut_config value, {source: value}) — every source that carries the
    # field must equal the dut_config.h value.
    checks = [
        ("service id", cfg.get("kServiceId"),
         {"vsomeip.json": vs["service"], "ets.fdepl": fd["service"]}),
        ("instance id", cfg.get("kInstanceId"),
         {"vsomeip.json": vs["instance"], "ets.fdepl": fd["instance"]}),
        ("TCP port", cfg.get("kTcpPort"),
         {"vsomeip.json": vs["tcp"], "ets.fdepl": fd["tcp"]}),
        ("UDP port", cfg.get("kUdpPort"),
         {"vsomeip.json": vs["udp"], "ets.fdepl": fd["udp"]}),
        ("SD port", cfg.get("kSdPort"), {"vsomeip.json": vs["sd_port"]}),
        ("SD multicast", cfg.get("kSdMcastGroup"), {"vsomeip.json": vs["sd_mcast"]}),
        ("application name", cfg.get("kApplicationName"),
         {"vsomeip.json/applications": vs["app_name"], "vsomeip.json/routing": vs["routing"]}),
    ]

    drift = []
    for label, dut_val, sources in checks:
        if dut_val is None:
            drift.append(f"{label}: missing from include/tc8/dut_config.h")
            continue
        for src, val in sources.items():
            if val != dut_val:
                drift.append(f"{label}: dut_config.h={dut_val!r} but {src}={val!r}")

    if drift:
        print("check_dut_identity: DUT identity drift across the three sources:",
              file=sys.stderr)
        for d in drift:
            print(f"  - {d}", file=sys.stderr)
        print("check_dut_identity: fix the source(s) so dut_config.h, vsomeip.json "
              "and ets.fdepl agree (see include/tc8/dut_config.h).", file=sys.stderr)
        return 1

    print(
        "check_dut_identity: OK - dut_config.h, vsomeip.json and ets.fdepl agree "
        f"(service=0x{cfg['kServiceId']:04X} instance=0x{cfg['kInstanceId']:04X} "
        f"tcp={cfg['kTcpPort']} udp={cfg['kUdpPort']} sd_port={cfg['kSdPort']} "
        f"sd_mcast={cfg['kSdMcastGroup']} app={cfg['kApplicationName']})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
