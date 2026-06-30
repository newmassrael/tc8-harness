#!/usr/bin/env python3
"""Generate the Python site mirror of the DHCPv4 BOOTP fixed-header decoder
from the single source src/sce_integration/dhcpv4_wire.def.

The .def is #included directly by the C++ authoritative decoder
(src/sce_integration/dhcpv4_wire.h, called from src/dissect/packet_pipeline.cpp),
so the C++ side cannot drift from it. This tool derives the Python decoder used
by the documentation-site tooling (site/scripts/decode_pcap.py) from the same
.def, so both languages share one layout. See docs/tech-debt.md TD-02.

Run with no args to (re)write the generated file; run with --check to verify it
is up to date (CI / pre-commit freshness gate). Both modes run a golden-vector
self-test (see tools/wire_gen_common.py) so a wrong offset/width in the .def
fails loudly rather than silently producing a consistent-but-wrong mirror.

Output:
  site/scripts/dhcpv4_wire_generated.py   imported by decode_pcap.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import wire_gen_common as common  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DEF = ROOT / "src/sce_integration/dhcpv4_wire.def"
PY_OUT = ROOT / "site/scripts/dhcpv4_wire_generated.py"
TOOL = "tools/gen_dhcpv4_wire.py"

# Data rows in the .def. Directive lines (#define/#undef ...) start with '#'
# and are skipped; trailing // comments are stripped before matching so rows
# may be documented inline. Anything left with a TC8_DHCP_ prefix must parse
# or it is a fat-fingered SSOT line — fail loud (a dropped row vanishes from
# the mirror while leaving the file green).
_FIELD_RE = re.compile(r"^TC8_DHCP_FIELD\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)$")
_ADDR_RE = re.compile(r"^TC8_DHCP_ADDR\(\s*(\w+)\s*,\s*(\w+)\s*\)$")
_BYTES_RE = re.compile(r"^TC8_DHCP_BYTES\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)$")
_CONST_RE = re.compile(r"^TC8_DHCP_CONST\(\s*(\w+)\s*,\s*(\w+)\s*\)$")


class Schema:
    def __init__(self):
        self.fields = []   # [("field"|"addr"|"bytes", member, off[, size|len])]
        self.consts = []   # [(name, raw_value_token)]


def parse() -> Schema:
    s = Schema()
    for raw in DEF.read_text(encoding="utf-8").splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith("TC8_DHCP_"):
            continue
        m = _FIELD_RE.match(line)
        if m is not None:
            member, off, size = m.groups()
            s.fields.append(("field", member, int(off, 0), int(size, 0)))
            continue
        m = _ADDR_RE.match(line)
        if m is not None:
            member, off = m.groups()
            s.fields.append(("addr", member, int(off, 0)))
            continue
        m = _BYTES_RE.match(line)
        if m is not None:
            member, off, length = m.groups()
            s.fields.append(("bytes", member, int(off, 0), int(length, 0)))
            continue
        m = _CONST_RE.match(line)
        if m is not None:
            name, value = m.groups()
            s.consts.append((name, value))
            continue
        sys.exit(f"gen_dhcpv4_wire: malformed .def row (TC8_DHCP_ prefix but "
                 f"unparseable): {raw!r}")
    if not (s.fields and s.consts):
        sys.exit("gen_dhcpv4_wire: parsed an incomplete schema — bad .def")
    return s


def render(s: Schema) -> str:
    desc = [
        "Python mirror of the DHCPv4 BOOTP fixed-header decode. The C++",
        "authoritative decoder (src/sce_integration/dhcpv4_wire.h) #includes",
        "the same .def directly, so this file and the harness share one layout.",
        "Imported by site/scripts/decode_pcap.py. The options TLV chain has no",
        "fixed offsets and is walked by the caller, outside this mirror.",
        "See docs/tech-debt.md TD-02.",
    ]
    lines = [
        common.banner(TOOL, "src/sce_integration/dhcpv4_wire.def", desc),
        "",
        "",
        common.PRELUDE.rstrip("\n"),
        "",
    ]
    for name, raw in s.consts:
        lines.append(f"{name} = {raw}")
    lines += ["", ""]

    lines.append("def decode_bootp_fixed_header(buf):")
    lines.append('    """RFC 951 / RFC 2131 BOOTP fixed header (op..chaddr).')
    lines.append('    Caller guarantees at least kOptionsOff bytes."""')
    lines.append("    return {")
    for row in s.fields:
        if row[0] == "field":
            _, member, off, size = row
            lines.append(f'        "{member}": _read(buf, {off}, {size}),')
        elif row[0] == "addr":
            _, member, off = row
            lines.append(f'        "{member}": _ipv4(buf, {off}),')
        else:  # bytes
            _, member, off, length = row
            lines.append(f'        "{member}": bytes(buf[{off}:{off} + {length}]),')
    lines.append("    }")
    lines += ["", ""]

    lines.append("def magic_cookie_valid(buf):")
    lines.append('    """True iff the 4 bytes at kMagicCookieOff equal the cookie."""')
    lines.append("    return _read(buf, kMagicCookieOff, 4) == kMagicCookie")
    lines.append("")
    return "\n".join(lines)


def self_test(module) -> list[str]:
    """Decode a hand-checked BOOTP vector and assert the field values, so a
    wrong offset/width in the .def is caught here rather than silently
    mirrored. Every fixed field carries a DISTINCT nonzero value so a wrong
    offset cannot alias another field's value (or a zero run) and pass."""
    problems: list[str] = []

    def check(label, got, want):
        if got != want:
            problems.append(f"{label}: got {got!r}, want {want!r}")

    # DHCPDISCOVER-shaped BOOTP fixed header (240 B) + option 53 = 1 + END.
    buf = bytearray(244)
    buf[0] = 1     # op = BOOTREQUEST
    buf[1] = 1     # htype = Ethernet
    buf[2] = 6     # hlen
    buf[3] = 2     # hops (distinct nonzero)
    buf[4:8] = (0x12345678).to_bytes(4, "big")    # xid
    buf[8:10] = (0x0102).to_bytes(2, "big")       # secs (distinct nonzero)
    buf[10:12] = (0x8000).to_bytes(2, "big")      # flags = BROADCAST
    buf[12:16] = bytes((10, 1, 2, 3))             # ciaddr (distinct)
    buf[16:20] = bytes((172, 16, 0, 5))           # yiaddr (distinct)
    buf[20:24] = bytes((192, 168, 7, 9))          # siaddr (distinct)
    buf[24:28] = bytes((169, 254, 11, 22))        # giaddr (distinct)
    buf[28:34] = bytes.fromhex("aabbccddeeff")    # chaddr MAC
    buf[236:240] = b"\x63\x82\x53\x63"            # magic cookie
    buf[240:244] = bytes((53, 1, 1, 255))         # opt 53 = DISCOVER, END

    f = module.decode_bootp_fixed_header(buf)
    check("op", f.get("op"), 1)
    check("htype", f.get("htype"), 1)
    check("hlen", f.get("hlen"), 6)
    check("hops", f.get("hops"), 2)
    check("xid", f.get("xid"), 0x12345678)
    check("secs", f.get("secs"), 0x0102)
    check("flags", f.get("flags"), 0x8000)
    check("ciaddr", f.get("ciaddr"), "10.1.2.3")
    check("yiaddr", f.get("yiaddr"), "172.16.0.5")
    check("siaddr", f.get("siaddr"), "192.168.7.9")
    check("giaddr", f.get("giaddr"), "169.254.11.22")
    check("chaddr_mac", bytes(f.get("chaddr", b"")[:6]), bytes.fromhex("aabbccddeeff"))
    check("cookie_ok", module.magic_cookie_valid(buf), True)

    bad = bytearray(buf)
    bad[236] = 0x00
    check("cookie_bad", module.magic_cookie_valid(bad), False)
    return problems


def main() -> int:
    return common.run("gen_dhcpv4_wire", ROOT, PY_OUT,
                      lambda: render(parse()), self_test, sys.argv)


if __name__ == "__main__":
    sys.exit(main())
