#!/usr/bin/env python3
"""Cross-check that the DUT identity agrees across every artifact that hand-encodes it.

The TC8 v3.0 spec leaves the DUT's <SERVICE-ID>/<INSTANCE>/<PORT>/app-name as
deployment parameters the tester chooses (§5.1.2.3). This project's chosen values
are written, by hand, in artifacts with distinct formats and purposes that MUST
agree, or a case binds/advertises the wrong endpoint and silently fails:

  PRIMARY identity (SERVICE-ID-1 0xF4E7 / instance 0x0001):
    - include/tc8/dut_config.h              C++ constants the harness/tester use
    - dut/dut_service/vsomeip.json          base vsomeip deployment
    - dut/dut_service/vsomeip-multi-instance.json
    - dut/dut_service/vsomeip-multi-service.json
    - dut/dut_service/vsomeip-multi-service-shared-port.json   spawn variants
    - dut/ets/ets.fdepl                     CommonAPI deployment (instance "ETS")
  SECONDARY identity (SERVICE-ID-1 instance 0x0002, and SERVICE-ID-2 0xF4E8) used
  by the multi-instance / multi-service cases, with C++ mirrors:
    - src/sce_integration/include/sce_integration/someip_method_dest.h  (kSi1Inst2*/kSi2UdpPort)
    - the variant vsomeip JSONs + dut/ets/ets.fdepl ("ETS2") + dut/ets/ets2.fdepl

These are distinct formats with no single SUPERSET source (vsomeip.json alone has
the SD multicast; ets.fdepl alone has method/event ids; dut_config.h alone has the
tester-side capture window), and partial codegen of a heavily-commented header is a
poor trade — so they stay hand-authored and this build-enforced cross-check keeps
them honest, the counterpart of the wire-`.def` `--check` gates. It is file-specific
where deployments deliberately diverge (e.g. vsomeip-multi-service-shared-port.json
intentionally reuses the primary ports for SERVICE-ID-2, so that file is NOT checked
against kSi2UdpPort). Pure-Python (json + re), no third-party deps.

Usage: python3 tools/check_dut_identity.py [--check]   (always checks; exit 1 on drift)
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class ParseError(Exception):
    """A source file could not be read or had an unexpected structure — reported as
    a clean gate failure rather than an uncaught traceback."""


def _read(rel):
    try:
        return (ROOT / rel).read_text()
    except OSError as e:
        raise ParseError(f"cannot read {rel}: {e}")


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


def parse_method_dest(text):
    return {
        m.group(1): int(m.group(2))
        for m in re.finditer(
            r"inline constexpr std::uint16_t\s+(k\w+)\s*=\s*(\d+)\s*;", text
        )
    }


def parse_vsomeip(rel):
    try:
        d = json.loads(_read(rel))
        services = {}
        for s in d["services"]:
            reliable = s.get("reliable")
            tcp = (
                int(reliable["port"]) if isinstance(reliable, dict)
                else int(reliable) if reliable is not None else None
            )
            services[(int(s["service"], 0), int(s["instance"], 0))] = {
                "tcp": tcp,
                "udp": int(s["unreliable"]) if s.get("unreliable") is not None else None,
            }
        sd = d.get("service-discovery", {})
        return {
            "unicast": d.get("unicast"),
            "app_name": d["applications"][0]["name"],
            "routing": d.get("routing"),
            "sd_mcast": sd.get("multicast"),
            "sd_port": int(sd["port"]) if sd.get("port") is not None else None,
            "services": services,
        }
    except (KeyError, IndexError, ValueError, TypeError) as e:
        raise ParseError(f"{rel}: unexpected structure ({type(e).__name__}: {e})")


def parse_fdepl(rel):
    """Interface-level service id + a {instance_id: {tcp,udp,unicast}} map keyed by
    SomeIpInstanceID. Each instance block runs from its SomeIpInstanceID line to the
    next (or EOF) — no brace matching, robust to layout/nesting changes."""
    text = _read(rel)
    sm = re.search(r"SomeIpServiceID\s*=\s*(0x[0-9A-Fa-f]+)", text)
    insts = list(re.finditer(r"SomeIpInstanceID\s*=\s*(0x[0-9A-Fa-f]+)", text))
    if not sm or not insts:
        raise ParseError(f"{rel}: no SomeIpServiceID / SomeIpInstanceID found")
    instances = {}
    for i, m in enumerate(insts):
        end = insts[i + 1].start() if i + 1 < len(insts) else len(text)
        block = text[m.end():end]

        def field(pat):
            mm = re.search(pat, block)
            return mm.group(1) if mm else None

        tcp = field(r"SomeIpReliableUnicastPort\s*=\s*(\d+)")
        udp = field(r"SomeIpUnreliableUnicastPort\s*=\s*(\d+)")
        instances[int(m.group(1), 0)] = {
            "tcp": int(tcp) if tcp else None,
            "udp": int(udp) if udp else None,
            "unicast": field(r'SomeIpUnicastAddress\s*=\s*"([^"]+)"'),
        }
    return {"service_id": int(sm.group(1), 0), "instances": instances}


def main():
    try:
        cfg = parse_dut_config(_read("include/tc8/dut_config.h"))
        md = parse_method_dest(_read("src/sce_integration/include/sce_integration/someip_method_dest.h"))
        json_names = (
            "vsomeip.json",
            "vsomeip-multi-instance.json",
            "vsomeip-multi-service.json",
            "vsomeip-multi-service-shared-port.json",
        )
        js = {n: parse_vsomeip(f"dut/dut_service/{n}") for n in json_names}
        ets = parse_fdepl("dut/ets/ets.fdepl")
        ets2 = parse_fdepl("dut/ets/ets2.fdepl")
    except ParseError as e:
        print(f"check_dut_identity: {e}", file=sys.stderr)
        return 1

    drift = []

    def expect(label, ref, named_values):
        if ref is None:
            drift.append(f"{label}: reference value is missing")
            return
        for src, val in named_values:
            if val is None:
                drift.append(f"{label}: {src} is missing it (expected {ref!r})")
            elif val != ref:
                drift.append(f"{label}: {src}={val!r} but expected {ref!r}")

    def svc(name, key, transport):
        s = js[name]["services"].get(key)
        return s[transport] if s else None

    si1, inst1 = cfg.get("kServiceId"), cfg.get("kInstanceId")
    prim = (si1, inst1)
    si2 = ets2["service_id"]

    # ---- primary identity (every artifact carries SERVICE-ID-1 / instance 0x0001) ----
    expect("primary service id", si1, [("ets.fdepl", ets["service_id"])])
    expect("primary instance id", inst1,
           [("ets.fdepl", inst1 if inst1 in ets["instances"] else None)]
           + [(n, inst1 if prim in js[n]["services"] else None) for n in json_names])
    expect("primary TCP port", cfg.get("kTcpPort"),
           [("ets.fdepl", ets["instances"].get(inst1, {}).get("tcp"))]
           + [(n, svc(n, prim, "tcp")) for n in json_names])
    expect("primary UDP port", cfg.get("kUdpPort"),
           [("ets.fdepl", ets["instances"].get(inst1, {}).get("udp"))]
           + [(n, svc(n, prim, "udp")) for n in json_names])
    expect("DUT unicast IP", ets["instances"].get(inst1, {}).get("unicast"),
           [("ets2.fdepl", ets2["instances"].get(0x0001, {}).get("unicast"))]
           + [(n, js[n]["unicast"]) for n in json_names])
    expect("application name", cfg.get("kApplicationName"),
           [(f"{n}/app", js[n]["app_name"]) for n in json_names]
           + [(f"{n}/routing", js[n]["routing"]) for n in json_names])
    expect("SD multicast", cfg.get("kSdMcastGroup"),
           [(n, js[n]["sd_mcast"]) for n in json_names])
    expect("SD port", cfg.get("kSdPort"),
           [(n, js[n]["sd_port"]) for n in json_names])

    # ---- secondary identity (file-specific; someip_method_dest.h names the file) ----
    expect("SERVICE-ID-1 instance 0x0002 TCP", md.get("kSi1Inst2TcpPort"),
           [("ets.fdepl ETS2", ets["instances"].get(0x0002, {}).get("tcp")),
            ("vsomeip-multi-instance.json", svc("vsomeip-multi-instance.json", (si1, 0x0002), "tcp"))])
    expect("SERVICE-ID-1 instance 0x0002 UDP", md.get("kSi1Inst2UdpPort"),
           [("ets.fdepl ETS2", ets["instances"].get(0x0002, {}).get("udp")),
            ("vsomeip-multi-instance.json", svc("vsomeip-multi-instance.json", (si1, 0x0002), "udp"))])
    expect("SERVICE-ID-2 UDP", md.get("kSi2UdpPort"),
           [("ets2.fdepl", ets2["instances"].get(0x0001, {}).get("udp")),
            ("vsomeip-multi-service.json", svc("vsomeip-multi-service.json", (si2, 0x0001), "udp"))])
    expect("SERVICE-ID-2 TCP", ets2["instances"].get(0x0001, {}).get("tcp"),
           [("vsomeip-multi-service.json", svc("vsomeip-multi-service.json", (si2, 0x0001), "tcp"))])

    if drift:
        print("check_dut_identity: DUT identity drift across the sources:", file=sys.stderr)
        for d in drift:
            print(f"  - {d}", file=sys.stderr)
        print("check_dut_identity: fix the source(s) so all named copies agree (see "
              "include/tc8/dut_config.h + src/sce_integration/include/sce_integration/someip_method_dest.h).",
              file=sys.stderr)
        return 1

    print(
        f"check_dut_identity: OK - primary 0x{si1:04X}/0x{inst1:04X} "
        f"tcp={cfg['kTcpPort']} udp={cfg['kUdpPort']} "
        f"ip={ets['instances'][inst1]['unicast']} app={cfg['kApplicationName']} "
        f"sd={cfg['kSdMcastGroup']}:{cfg['kSdPort']}; secondary inst2 "
        f"{md['kSi1Inst2TcpPort']}/{md['kSi1Inst2UdpPort']} si2 0x{si2:04X} "
        f"udp={md['kSi2UdpPort']}; checked {len(json_names)} vsomeip JSONs + "
        f"2 fdepl + 2 C++ headers"
    )
    return 0


if __name__ == "__main__":
    extra = [a for a in sys.argv[1:] if a != "--check"]
    if extra:
        print(f"check_dut_identity: unknown argument(s): {' '.join(extra)} "
              "(only --check is accepted)", file=sys.stderr)
        sys.exit(2)
    sys.exit(main())
