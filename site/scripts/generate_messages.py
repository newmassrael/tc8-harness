#!/usr/bin/env python3
"""Auto-generate per-packet ``messages[]`` annotations from SCXML cond rules.

Reads ``site/src/data/cases/<CASE>.json`` for the inlined SCXML and
``site/src/data/pcap/<CASE>.json`` for the per-case packet list, walks
the SCXML state machine packet-by-packet, and emits a labelled JSON file
at ``site/src/data/auto_messages/<CASE>.json``. The site's
``localizedMessages`` helper merges these auto labels with hand-written
locale overrides at idx granularity (manual wins).

Usage:
    site/scripts/generate_messages.py                # all cases with pcap
    site/scripts/generate_messages.py --only ARP_03  # one case

Design notes:
- No ``eval`` and no external dependencies. Cond expressions use a small
  hand-written tokenizer + recursive-descent parser tied to the cond
  grammar tc8-harness actually writes (captured.X / expected.Y member
  access, indexed sd_entries, bitwise & + comparisons, ``and`` / ``or`` /
  ``not`` joins, captured.method(...) helpers, scoped constants).
- ``expected.X`` resolves through a runtime-config loader that parses
  ``dut/env/smoke-test.sh``'s ``--expect name=value`` blocks plus the
  DHCPv4 default-endpoint constants. Anything not represented in those
  sources stays UNKNOWN. Per-capture identity fields (``dut_iface_mac``,
  ``tester_mac``) come from the pcap manifest's auto-detected endpoints.
- ``::tc8::sce::tcp::kFoo`` scoped constants resolve through a regex
  parser over ``src/sce_integration/tcp_pilot_common.h`` that handles
  simple integer arithmetic across constant cross-refs.
- ``captured.is_pure_dut_ack(...)`` / ``is_dut_rst`` / ``is_dut_fin_ack``
  / ``is_dut_syn`` / ``is_dut_data_segment`` are reimplemented in Python
  so TCP guard chains that wrap the 4-tuple check in a single call still
  evaluate when their args resolve.
- Three-valued Kleene logic. Pass/progress transitions use lenient mode
  (UNKNOWN drops from AND when concrete TRUE settles the result) plus a
  DUT-direction guard. Fail transitions use strict mode (UNKNOWN poisons)
  so an ``X != expected.Y`` clause can't false-fire when expected.Y is
  still missing.
- Output is locale-neutral English. Localised override files keep
  responsibility for translation; this generator never writes Korean.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CASES_DIR = REPO_ROOT / "site" / "src" / "data" / "cases"
DEFAULT_PCAP_DIR = REPO_ROOT / "site" / "src" / "data" / "pcap"
DEFAULT_OUT_DIR = REPO_ROOT / "site" / "src" / "data" / "auto_messages"

# Runtime-overridable paths; the pcap-refresh workflow points these at
# the orphan pcap-data branch checkout so generator output sits next to
# decoded pcap JSON in the same commit.
CASES_DIR = DEFAULT_CASES_DIR
PCAP_DIR = DEFAULT_PCAP_DIR
OUT_DIR = DEFAULT_OUT_DIR

GENERATOR_VERSION = "2"


# ---------------------------------------------------------------------------
# Runtime-config loaders
#
# The harness puts the values that satisfy ``expected.X`` cond clauses
# into two places:
#   * ``dut/env/smoke-test.sh`` — protocol-prefixed ``--expect`` blocks
#     (TC8_DUT_EXPECT / ARP_DUT_EXPECT_STATIC / ICMPV4 / IPV4)
#   * ``src/sce_integration/dhcpv4_default_endpoints.h`` — constexpr
#     server / offered-IP defaults
# Plus scoped TCP constants live in
# ``src/sce_integration/tcp_pilot_common.h`` as a flat ``inline constexpr``
# table referenced by name via ``::tc8::sce::tcp::kFoo`` from SCXML cond
# clauses (and from per-case overrides that add offsets).
# ---------------------------------------------------------------------------


SMOKE_TEST_PATH = REPO_ROOT / "dut" / "env" / "smoke-test.sh"
DHCPV4_CONSTS_PATH = REPO_ROOT / "src" / "sce_integration" / "dhcpv4_default_endpoints.h"
TCP_CONSTS_PATH = REPO_ROOT / "src" / "sce_integration" / "tcp_pilot_common.h"
# SOMEIP-SD option-type / l4-proto enum-equivalents — surface the same way
# as the TCP pilot constants so cond fragments like
# ``::tc8::sd_option_type::kIpv4Endpoint`` resolve to the integer value.
SOMEIP_CAPTURED_PATH = REPO_ROOT / "src" / "sce_integration" / "someip_captured.h"


def _coerce_value(raw: str) -> Any:
    """Turn a smoke-test.sh ``--expect`` RHS into a Python value the
    evaluator can compare against captured fields. IP strings stay as
    dotted strings (matches the decoder's ``src_ip`` / ``dst_ip``
    representation); MACs stay lowercased; integers parse from hex or
    decimal with optional 0x prefix.

    Returns ``None`` for unexpanded ``$VAR`` literals so the pcap-derived
    endpoint identity (``_pcap_endpoint_expects``) can fill the slot
    instead of pinning a placeholder.
    """
    s = raw.strip().strip('"').strip("'")
    if not s:
        return None
    # Unexpanded shell variable — caller should drop and let the pcap
    # manifest's auto-detected MAC/IP take over.
    if s.startswith("$"):
        return None
    # Dotted-quad IPv4 — keep as string for direct dotted-string match
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", s):
        return s
    # MAC — normalise case so it matches decoder output
    if re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", s):
        return s.lower()
    # Hex / dec integer
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except ValueError:
        return s


def _load_smoke_test_expects(path: Path = SMOKE_TEST_PATH) -> dict[str, Any]:
    """Build a flat ``{key: value}`` dict of every ``--expect`` value
    declared at file scope in smoke-test.sh. Protocol-prefixed keys
    (``arp.tester_ip``) are stored under their bare name (``tester_ip``)
    plus the prefixed form, so a SCXML cond can reach them either way.

    Variable substitutions (``$TESTER_IP4``, ``$DUT_IP4``,
    ``$ICMPV4_TESTER_ECHO_ID``, etc.) are resolved against a shell-var
    scan over the same file — limited to the top-of-file fixture block.
    Per-worker dynamic values (``$dut_mac``) stay unresolved and fall
    back to UNKNOWN; the pcap manifest's auto-detected ``dut_mac`` /
    ``tester_mac`` cover that gap (see ``_pcap_endpoint_expects``).
    """
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")

    # First pass: shell-vars at the top of the file (FOO=bar form).
    shell_vars: dict[str, str] = {}
    for m in re.finditer(r"^([A-Z][A-Z0-9_]*)=([^\s#$()]+)\s*$",
                         text, re.MULTILINE):
        shell_vars.setdefault(m.group(1), m.group(2))

    def expand(s: str) -> str:
        return re.sub(r"\$([A-Z][A-Z0-9_]*)",
                      lambda m: shell_vars.get(m.group(1), m.group(0)), s)

    out: dict[str, Any] = {}
    # Every line of the shape ``--expect name=value`` (possibly quoted).
    # Protocol-namespaced keys (e.g. ``arp.tester_ip``) stay namespaced;
    # the resolver picks the right namespace at lookup time based on
    # the case's category prefix so values don't pollute across
    # protocols (the unprefixed ``tester_ip`` from the SOME/IP block
    # otherwise leaks into ARP / ICMPv4 expectations).
    for m in re.finditer(
        r'--expect\s+"?([A-Za-z_][A-Za-z_0-9.]*)=([^"\s)]+)"?',
        text,
    ):
        raw_key, raw_val = m.group(1), m.group(2)
        val = _coerce_value(expand(raw_val))
        if val is None:
            continue
        out[raw_key] = val
    return out


def _load_smoke_test_case_overrides(path: Path = SMOKE_TEST_PATH) -> dict[str, dict[str, Any]]:
    """Capture per-case ``CASE_EXPECT_OVERRIDES`` entries from
    smoke-test.sh. Each entry has the form
    ``[CASE_ID]="key=value[,key=value...]"`` and last-wins per the
    harness's ``expect_parser``. Returns ``{case_id: {key: value}}``;
    callers merge over the global expects."""
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")
    out: dict[str, dict[str, Any]] = {}
    for m in re.finditer(
        r'^\s*\[([A-Z][A-Z0-9_]+)\]\s*=\s*"([^"\n]*=[^"\n]*)"',
        text, re.MULTILINE,
    ):
        cid = m.group(1)
        rhs = m.group(2)
        parsed: dict[str, Any] = {}
        for pair in rhs.split(","):
            if "=" not in pair:
                continue
            k, _, v = pair.partition("=")
            val = _coerce_value(v)
            if val is None:
                continue
            parsed[k.strip()] = val
        if parsed:
            out.setdefault(cid, {}).update(parsed)
    return out


def _decode_be32_shift_block(body: str) -> int | None:
    """Decode a 4-line ``(BYTE << 0) | (BYTE << 8) | (BYTE << 16) |
    (BYTE << 24)`` constant declaration into the resulting u32 value.

    DHCPv4 default endpoints use this idiom; the comment on the
    preceding line carries the dotted-decimal but we parse the
    expression directly so the source-of-truth stays the C++."""
    nums = re.findall(
        r"<\s*(?:std::|::)?u?int32_t\s*>\(\s*(\d+)U?\s*\)\s*<<\s*(\d+)",
        body,
    )
    if len(nums) != 4:
        return None
    val = 0
    for byte_s, shift_s in nums:
        val |= (int(byte_s) & 0xFF) << int(shift_s)
    return val


def _u32_be_to_dotted(value: int) -> str:
    """``kDefaultServerIdBe`` stores the IPv4 in little-endian-shifted
    form (byte 0 = MSB of the dotted form). Recover the dotted string."""
    return ".".join(str((value >> (i * 8)) & 0xFF) for i in range(4))


def _load_dhcpv4_default_consts(path: Path = DHCPV4_CONSTS_PATH) -> dict[str, Any]:
    """Pull the ``kDefault*`` / ``kSecond*`` u32 IP constants out of
    dhcpv4_default_endpoints.h and surface them under both their bare
    name and (the same name, e.g. ``server_id_be``) so they're reachable
    from ``expected.server_id_be`` cond fragments."""
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")
    out: dict[str, Any] = {}
    for m in re.finditer(
        r"inline\s+constexpr\s+std::uint32_t\s+(\w+)\s*=([^;]+);",
        text,
    ):
        name, body = m.group(1), m.group(2)
        val = _decode_be32_shift_block(body)
        if val is None:
            # Plain integer constant
            mn = re.search(r"=\s*([0-9]+)U?\s*;", m.group(0))
            if mn:
                val = int(mn.group(1))
            else:
                continue
        out[name] = val
        # Map kFooBar → foo_bar (SCXML conds reference snake_case names)
        snake = re.sub(r"(?<!^)(?=[A-Z])", "_", name.lstrip("k")).lower()
        out.setdefault(snake, val)
        # IP-shaped fields: also expose the dotted-string form so equality
        # comparisons against pcap-decoder strings work without an extra
        # conversion layer at eval time.
        if snake.endswith("_be") or snake.endswith("_ip"):
            out.setdefault(snake.removesuffix("_be"), _u32_be_to_dotted(val))
    return out


_NAMESPACE_OPEN_RE = re.compile(r"^\s*namespace\s+(\w+)\s*\{", re.MULTILINE)
_NAMESPACE_CLOSE_RE = re.compile(r"^\s*\}\s*//.*?namespace", re.MULTILINE)


def _scan_namespace_blocks(text: str) -> list[tuple[str, int, int]]:
    """Return ``[(namespace, body_start, body_end)]`` for every named
    namespace block in ``text``. Nested namespaces produce nested
    ranges — the resolver picks the innermost match.

    Pairing is stack-based over the merged stream of open/close
    positions so a nested namespace doesn't accidentally swallow its
    parent's closing brace. Both regexes only match the documented
    forms used in this repo's headers (``namespace foo {`` open,
    ``} // namespace`` close); inline braces from class definitions
    don't match either pattern.
    """
    events: list[tuple[int, str, str]] = []  # (pos, "open"/"close", name)
    for m in _NAMESPACE_OPEN_RE.finditer(text):
        events.append((m.end(), "open", m.group(1)))
    for m in _NAMESPACE_CLOSE_RE.finditer(text):
        events.append((m.start(), "close", ""))
    events.sort(key=lambda e: e[0])
    blocks: list[tuple[str, int, int]] = []
    stack: list[tuple[str, int]] = []  # (name, body_start)
    for pos, kind, name in events:
        if kind == "open":
            stack.append((name, pos))
        elif stack:
            ns_name, body_start = stack.pop()
            blocks.append((ns_name, body_start, pos))
    return blocks


def _namespace_of(blocks: list[tuple[str, int, int]], pos: int) -> str:
    """Find the innermost namespace that brackets ``pos``. Returns "" for
    file-scope declarations."""
    enclosing = ""
    smallest_range = float("inf")
    for name, start, end in blocks:
        if start <= pos < end:
            rng = end - start
            if rng < smallest_range:
                smallest_range = rng
                enclosing = name
    return enclosing


def _load_scoped_consts(paths: tuple[Path, ...] = (TCP_CONSTS_PATH, SOMEIP_CAPTURED_PATH)) -> dict[tuple[str, str], int]:
    """Two-pass parse over a set of headers: capture every
    ``inline constexpr <int-ish-type> NAME = EXPR;`` line (tagged with
    the innermost namespace it lives in), then resolve EXPR using the
    partially-populated map. Handles cross-references like
    ``kTcpMssOptionsTesterSrcPort02 = kBasicsTesterPort + 52U`` without
    needing a full C++ parser.

    Two sources today: ``tcp_pilot_common.h`` (port offsets referenced
    by TCP cases via ``::tc8::sce::tcp::kFoo``) and ``someip_captured.h``
    (option types, l4 protos, multi-service identities, SD test
    sentinels referenced via ``::tc8::<ns>::kFoo``).

    Returns ``{(namespace, name): int}``. Namespace-aware so the two
    ``kServiceId`` constants in someip_captured.h (``someipsrv_si2`` =
    0xF4E8 vs ``sd_test_unknown`` = 0xFFFE) don't collide.

    Non-integer / time-typed constants (``std::chrono::milliseconds``)
    are skipped — the SCXML grammar only references integer values.
    """
    raw: dict[tuple[str, str], str] = {}
    name_to_namespaces: dict[str, list[str]] = {}
    for path in paths:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        blocks = _scan_namespace_blocks(text)
        for m in re.finditer(
            r"^inline\s+constexpr\s+(?:std::)?(?:uint|int)\w*_t\s+(\w+)\s*=\s*([^;]+);",
            text, re.MULTILINE,
        ):
            name = m.group(1)
            ns = _namespace_of(blocks, m.start())
            key = (ns, name)
            raw.setdefault(key, m.group(2).strip())
            name_to_namespaces.setdefault(name, []).append(ns)

    out: dict[tuple[str, str], int] = {}
    resolving: set[tuple[str, str]] = set()

    def resolve(name: str, current_ns: str = "") -> int | None:
        # When an expression references another constant by bare name,
        # search the current namespace first (intra-block cross-refs are
        # the common shape), then file scope as a fallback. Single match
        # only — ambiguous bare names stay None.
        candidates = [(current_ns, name), ("", name)]
        # Plus any other namespace that defines this exact bare name.
        for ns in name_to_namespaces.get(name, []):
            if (ns, name) not in candidates:
                candidates.append((ns, name))
        for key in candidates:
            if key in out:
                return out[key]
            if key in raw and key not in resolving:
                resolving.add(key)
                try:
                    v = _eval_int_expr(raw[key], lambda n: resolve(n, key[0]))
                finally:
                    resolving.discard(key)
                if v is not None:
                    out[key] = v
                    return v
        return None

    for k in list(raw):
        resolve(k[1], k[0])
    return out


_INT_EXPR_TOKEN_RE = re.compile(r"""
    \s+ |
    (?P<HEX>0[xX][0-9A-Fa-f]+[Uu]?[Ll]?[Ll]?) |
    (?P<INT>\d+[Uu]?[Ll]?[Ll]?) |
    (?P<NAME>[A-Za-z_][A-Za-z0-9_]*) |
    (?P<OP>[+\-*/&|()])
""", re.VERBOSE)


def _eval_int_expr(expr: str, resolve_name) -> int | None:
    """Evaluate a tiny integer expression (literals + names + +-*/&|()).
    Names get resolved through the caller-supplied callback so we
    support cross-references between ``inline constexpr`` declarations.

    Returns ``None`` on any unsupported construct so a stray
    ``std::chrono::milliseconds(...)`` line silently drops out of the
    constant table without poisoning the rest of the parse."""
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(expr):
        m = _INT_EXPR_TOKEN_RE.match(expr, pos)
        if not m:
            return None
        pos = m.end()
        if m.lastgroup is None:
            continue
        tokens.append((m.lastgroup, m.group()))

    # Tiny recursive-descent: + and -, then * / & |, then unary - and primary
    idx = 0

    def peek():
        return tokens[idx] if idx < len(tokens) else None

    def consume():
        nonlocal idx
        t = tokens[idx]
        idx += 1
        return t

    def primary() -> int | None:
        nonlocal idx
        t = peek()
        if t is None:
            return None
        kind, txt = t
        if kind == "OP" and txt == "(":
            consume()
            v = add_sub()
            t2 = peek()
            if t2 and t2[1] == ")":
                consume()
            return v
        if kind == "OP" and txt == "-":
            consume()
            v = primary()
            return None if v is None else -v
        if kind == "HEX":
            consume()
            return int(txt.rstrip("uUlL"), 16)
        if kind == "INT":
            consume()
            return int(txt.rstrip("uUlL"))
        if kind == "NAME":
            consume()
            return resolve_name(txt)
        return None

    def mul_div() -> int | None:
        v = primary()
        while v is not None:
            t = peek()
            if t is None or t[0] != "OP" or t[1] not in ("*", "/", "&", "|"):
                break
            op = consume()[1]
            r = primary()
            if r is None:
                return None
            if op == "*": v = v * r
            elif op == "/": v = v // r if r else None
            elif op == "&": v = v & r
            elif op == "|": v = v | r
        return v

    def add_sub() -> int | None:
        v = mul_div()
        while v is not None:
            t = peek()
            if t is None or t[0] != "OP" or t[1] not in ("+", "-"):
                break
            op = consume()[1]
            r = mul_div()
            if r is None:
                return None
            v = v + r if op == "+" else v - r
        return v

    return add_sub()


_KNOWN_TESTER_INJECTED_MACS = {
    "02:00:00:00:00:a1",  # ARP_TESTER_INJECTED_MAC
    "02:00:00:00:00:a2",  # ARP_TESTER_INJECTED_MAC2
    "02:00:00:00:00:a3",  # ARP_TESTER_INJECTED_MAC3
}


def _pcap_endpoint_expects(pcap_doc: dict) -> dict[str, Any]:
    """Surface per-capture identity (MACs) under the keys SCXML conds
    reference. The DUT MAC is kernel-assigned per veth pair so it can
    only be read from the pcap manifest's auto-detected endpoints.

    The decoder's ``_autodetect_endpoints`` picks "first emitter is the
    tester" — fine for ARP / ICMPv4 / SOME/IP where the tester drives
    the stimulus, but inverted for DHCP / TCP active-OPEN where the DUT
    emits first. Two corrections compensate:

    1. If the auto-detected ``dut_mac`` matches a known ARP injected
       MAC (kTesterInjectedMac family), the autodetect got the labels
       backwards — swap before exporting.
    2. For DHCP captures, the ``chaddr`` field on the BOOTP header is
       the client's hardware address by RFC 2131 §2 — i.e. the DUT.
       Override ``dut_iface_mac`` from the first DHCP frame's chaddr
       so DHCP conds resolve correctly even when (1) doesn't apply.
    """
    out: dict[str, Any] = {}
    dut_mac = (pcap_doc.get("dut_mac") or "").lower()
    tester_mac = (pcap_doc.get("tester_mac") or "").lower()
    if dut_mac and dut_mac in _KNOWN_TESTER_INJECTED_MACS:
        dut_mac, tester_mac = tester_mac, dut_mac
    if dut_mac:
        out["dut_iface_mac"] = dut_mac
        out["dut_real_mac"] = dut_mac
    if tester_mac:
        out["pcap_tester_mac"] = tester_mac

    # DHCP chaddr override: scan the first packet that carries a chaddr.
    for p in pcap_doc.get("packets") or []:
        ch = (p.get("fields") or {}).get("chaddr")
        if isinstance(ch, str) and ch:
            out["dut_iface_mac"] = ch.lower()
            out["dut_real_mac"] = ch.lower()
            break
    return out


# case-id prefix → ordered list of namespaces to consult in smoke-test.sh.
# The harness applies *all* ``--expect`` blocks at every case start (see
# ``expect_args`` in ``dut/env/smoke-test.sh:run_case``); routing to a
# specific expected struct happens via the SCXML's ``cpp:type``. TCP /
# UDP SCXMLs use ``Ipv4Expected`` so their ``expected.dut_iface_ip``
# reads from the ``ipv4.*`` block; DHCPv4 routes both ``dhcpv4.*`` and
# the constexpr defaults from dhcpv4_default_endpoints.h.
CATEGORY_TO_NS_CHAIN = {
    "ARP":              ("arp",),
    "ICMPV4":           ("icmpv4",),
    "IPV4_AUTOCONF":    ("ipv4",),
    "IPV4":             ("ipv4",),
    "UDP":              ("udp", "ipv4"),
    "DHCPV4":           ("dhcpv4", "ipv4"),
    "TCP":              ("tcp", "ipv4"),
    "SOMEIPSRV":        ("someip",),
    "SOMEIP_ETS":       ("someip",),
}


def _ns_chain_for_case(case_id: str) -> tuple[str, ...]:
    cid = case_id.upper()
    # Longest-prefix wins (IPV4_AUTOCONF before IPV4).
    for prefix in sorted(CATEGORY_TO_NS_CHAIN, key=len, reverse=True):
        if cid.startswith(prefix + "_") or cid == prefix:
            return CATEGORY_TO_NS_CHAIN[prefix]
    return ()


def build_expected_dict(case_id: str, pcap_doc: dict) -> dict[str, Any]:
    """Layered lookup. Namespaced smoke-test values first in priority
    order (e.g. ``tcp.*`` then ``ipv4.*`` for TCP cases), then unprefixed
    smoke-test values for SOME/IP, then DHCPv4 constexpr defaults
    (mapped to the ``server_id_be`` / ``offered_ip_be`` field names the
    SCXML expects via dhcpv4_expected.h), then per-capture identity.

    Earliest layer wins so a protocol-specific override (ARP's injected
    MAC) doesn't get shadowed by a less-specific value from a later
    namespace.
    """
    chain = _ns_chain_for_case(case_id)
    sm = smoke_expects()
    pe = _pcap_endpoint_expects(pcap_doc)
    dh = dhcp_consts()

    out: dict[str, Any] = {}
    for ns in chain:
        for k, v in sm.items():
            if k.startswith(ns + "."):
                out.setdefault(k[len(ns) + 1:], v)
    # SOME/IP block uses bare (unprefixed) keys; apply only for someip.
    if "someip" in chain:
        for k, v in sm.items():
            if "." not in k:
                out.setdefault(k, v)
    # DHCPv4 default endpoints — the dhcpv4_expected.h struct binds the
    # ``server_id_be`` / ``offered_ip_be`` / ``second_server_id_be``
    # fields to ``kDefaultServerIdBe`` / ``kDefaultOfferedIpBe`` /
    # ``kSecondServerIdBe``. We surface those bindings here so the
    # SCXML's ``expected.server_id_be`` resolves to the constant value
    # without needing a C++ parser.
    if "dhcpv4" in chain:
        for field_name, const_name in [
            ("server_id_be",        "kDefaultServerIdBe"),
            ("offered_ip_be",       "kDefaultOfferedIpBe"),
            ("second_server_id_be", "kSecondServerIdBe"),
        ]:
            v = dh.get(const_name)
            if v is not None:
                out.setdefault(field_name, v)
                out.setdefault(field_name.removesuffix("_be"),
                               _u32_be_to_dotted(v))
    # Per-capture identity available to every case.
    for k, v in pe.items():
        out.setdefault(k, v)
    # Per-case overrides (CASE_EXPECT_OVERRIDES dict in smoke-test.sh)
    # win — they're the harness's last-wins ``--expect`` append for the
    # specific case. SOMEIP_ETS_147 flipping eventgroup_id from 0x0001
    # to 0x0002 is the canonical example.
    for k, v in smoke_case_overrides().get(case_id.upper(), {}).items():
        out[k] = v
    return out


# Cached loaders — file IO once per process.
_SMOKE_EXPECTS: dict[str, Any] | None = None
_SMOKE_CASE_OVERRIDES: dict[str, dict[str, Any]] | None = None
_DHCP_CONSTS: dict[str, Any] | None = None
_SCOPED_CONSTS: dict[str, int] | None = None


def smoke_expects() -> dict[str, Any]:
    global _SMOKE_EXPECTS
    if _SMOKE_EXPECTS is None:
        _SMOKE_EXPECTS = _load_smoke_test_expects()
    return _SMOKE_EXPECTS


def smoke_case_overrides() -> dict[str, dict[str, Any]]:
    global _SMOKE_CASE_OVERRIDES
    if _SMOKE_CASE_OVERRIDES is None:
        _SMOKE_CASE_OVERRIDES = _load_smoke_test_case_overrides()
    return _SMOKE_CASE_OVERRIDES


def dhcp_consts() -> dict[str, Any]:
    global _DHCP_CONSTS
    if _DHCP_CONSTS is None:
        _DHCP_CONSTS = _load_dhcpv4_default_consts()
    return _DHCP_CONSTS


def scoped_consts() -> dict[str, int]:
    global _SCOPED_CONSTS
    if _SCOPED_CONSTS is None:
        _SCOPED_CONSTS = _load_scoped_consts()
    return _SCOPED_CONSTS


# ---------------------------------------------------------------------------
# Cond tokenizer
# ---------------------------------------------------------------------------


TOKEN_SPEC = [
    ("WS",      r"\s+"),
    ("HEX",     r"0[xX][0-9A-Fa-f]+[Uu]?[Ll]?[Ll]?"),
    ("INT",     r"\d+[Uu]?[Ll]?[Ll]?"),
    ("CMP",     r"==|!=|<=|>="),
    ("LE",      r"<"),
    ("GE",      r">"),
    ("ANDAND",  r"&&"),
    ("OROR",    r"\|\|"),
    ("AMP",     r"&"),
    ("PIPE",    r"\|"),
    ("PLUS",    r"\+"),
    ("MINUS",   r"-"),
    ("STAR",    r"\*"),
    ("SLASH",   r"/"),
    ("BANG",    r"!"),
    ("LPAREN",  r"\("),
    ("RPAREN",  r"\)"),
    ("LBRACK",  r"\["),
    ("RBRACK",  r"\]"),
    ("LBRACE",  r"\{"),
    ("RBRACE",  r"\}"),
    ("DOT",     r"\."),
    ("COMMA",   r","),
    ("SCOPE",   r"::"),
    ("IDENT",   r"[A-Za-z_][A-Za-z0-9_]*"),
]
TOKEN_RE = re.compile("|".join(f"(?P<{n}>{p})" for n, p in TOKEN_SPEC))

KEYWORDS = {"and", "or", "not", "true", "false"}


@dataclass
class Token:
    kind: str
    text: str


def tokenize(src: str) -> list[Token]:
    out: list[Token] = []
    pos = 0
    while pos < len(src):
        m = TOKEN_RE.match(src, pos)
        if not m:
            raise ValueError(f"unexpected char at pos {pos}: {src[pos]!r}")
        kind = m.lastgroup
        text = m.group()
        pos = m.end()
        if kind == "WS":
            continue
        if kind == "IDENT" and text in KEYWORDS:
            kind = text.upper()  # AND / OR / NOT / TRUE / FALSE
        out.append(Token(kind, text))  # type: ignore[arg-type]
    return out


# ---------------------------------------------------------------------------
# Cond AST
# ---------------------------------------------------------------------------


@dataclass
class IntLit:
    value: int


@dataclass
class BoolLit:
    value: bool


@dataclass
class Ident:
    """Dotted/indexed name. Parts are str (member) or int (index)."""
    parts: tuple


@dataclass
class BinOp:
    op: str
    lhs: Any
    rhs: Any


@dataclass
class UnOp:
    op: str
    operand: Any


@dataclass
class Call:
    """Opaque function/method call — always evaluates to UNKNOWN."""
    target: Any
    args: list


@dataclass
class InitList:
    """``{ a, b, c }`` — opaque, used only as an argument to opaque calls."""
    items: list


@dataclass
class Opaque:
    """Anything else we couldn't classify — evaluates to UNKNOWN."""
    note: str = ""


@dataclass
class ScopedConst:
    """``::tc8::<...>::kFoo`` form — resolves against the constant table
    at eval time. ``namespace`` is the immediate enclosing namespace
    name (the segment immediately before ``kFoo``); ``name`` is the
    identifier. The two together disambiguate the kServiceId clash
    between ``someipsrv_si2`` (0xF4E8) and ``sd_test_unknown`` (0xFFFE)
    in someip_captured.h."""
    name: str
    namespace: str = ""


@dataclass
class Member:
    """``<call-or-other>.field`` chain. Only emitted when the base of the
    member access isn't a plain ``captured.X`` / ``expected.X`` Ident
    (those keep using ``Ident`` with extra ``parts``). Today the only
    producer is ``captured.sd_first_option_with_l4(...).field`` —
    the helper returns a dict and Member's eval reads ``.field`` out
    of it."""
    target: Any
    name: str


# ---------------------------------------------------------------------------
# Cond parser (recursive descent)
# ---------------------------------------------------------------------------


class Parser:
    def __init__(self, tokens: list[Token]) -> None:
        self.toks = tokens
        self.pos = 0

    def peek(self, k: int = 0) -> Token | None:
        i = self.pos + k
        return self.toks[i] if i < len(self.toks) else None

    def take(self) -> Token:
        tok = self.toks[self.pos]
        self.pos += 1
        return tok

    def accept(self, *kinds: str) -> Token | None:
        t = self.peek()
        if t and t.kind in kinds:
            return self.take()
        return None

    def expect(self, kind: str) -> Token:
        t = self.peek()
        if not t or t.kind != kind:
            raise ValueError(f"expected {kind} at pos {self.pos}, got {t}")
        return self.take()

    def parse(self) -> Any:
        expr = self.or_expr()
        if self.peek() is not None:
            # Trailing garbage — wrap whole expression as opaque to keep
            # the generator from crashing on edge-case grammar.
            return Opaque(note="trailing tokens")
        return expr

    def or_expr(self) -> Any:
        lhs = self.and_expr()
        while self.accept("OR", "OROR"):
            rhs = self.and_expr()
            lhs = BinOp("or", lhs, rhs)
        return lhs

    def and_expr(self) -> Any:
        lhs = self.not_expr()
        while self.accept("AND", "ANDAND"):
            rhs = self.not_expr()
            lhs = BinOp("and", lhs, rhs)
        return lhs

    def not_expr(self) -> Any:
        if self.accept("NOT", "BANG"):
            return UnOp("not", self.not_expr())
        return self.cmp_expr()

    def cmp_expr(self) -> Any:
        lhs = self.bitor()
        t = self.peek()
        if t and t.kind in ("CMP", "LE", "GE"):
            op_text = self.take().text
            rhs = self.bitor()
            return BinOp(op_text, lhs, rhs)
        return lhs

    def bitor(self) -> Any:
        lhs = self.bitand()
        while self.accept("PIPE"):
            rhs = self.bitand()
            lhs = BinOp("|", lhs, rhs)
        return lhs

    def bitand(self) -> Any:
        lhs = self.add()
        while self.accept("AMP"):
            rhs = self.add()
            lhs = BinOp("&", lhs, rhs)
        return lhs

    def add(self) -> Any:
        lhs = self.mul()
        while True:
            t = self.peek()
            if t and t.kind == "PLUS":
                self.take()
                lhs = BinOp("+", lhs, self.mul())
            elif t and t.kind == "MINUS":
                self.take()
                lhs = BinOp("-", lhs, self.mul())
            else:
                break
        return lhs

    def mul(self) -> Any:
        lhs = self.unary()
        while True:
            t = self.peek()
            if t and t.kind == "STAR":
                self.take()
                lhs = BinOp("*", lhs, self.unary())
            elif t and t.kind == "SLASH":
                self.take()
                lhs = BinOp("/", lhs, self.unary())
            else:
                break
        return lhs

    def unary(self) -> Any:
        if self.accept("MINUS"):
            return UnOp("-", self.unary())
        return self.atom()

    def atom(self) -> Any:
        t = self.peek()
        if t is None:
            raise ValueError("unexpected end of expression")
        if t.kind == "HEX":
            self.take()
            return IntLit(int(t.text.rstrip("uUlL"), 16))
        if t.kind == "INT":
            self.take()
            return IntLit(int(t.text.rstrip("uUlL")))
        if t.kind == "TRUE":
            self.take()
            return BoolLit(True)
        if t.kind == "FALSE":
            self.take()
            return BoolLit(False)
        if t.kind == "LPAREN":
            self.take()
            inner = self.or_expr()
            self.expect("RPAREN")
            return inner
        if t.kind == "LBRACE":
            return self.init_list()
        if t.kind == "SCOPE" or t.kind == "IDENT":
            return self.primary()
        # Unknown atom shape — opaque so we don't blow up
        self.take()
        return Opaque(note=f"unexpected atom {t.text!r}")

    def init_list(self) -> InitList:
        self.expect("LBRACE")
        items: list[Any] = []
        while self.peek() and self.peek().kind != "RBRACE":  # type: ignore[union-attr]
            items.append(self.or_expr())
            if not self.accept("COMMA"):
                break
        self.expect("RBRACE")
        return InitList(items=items)

    def primary(self) -> Any:
        """Identifier chain: optional ``::`` prefix, dots, [index], (args)."""
        parts: list = []
        scoped_idents: list[str] = []

        # Leading or interior scope (``::tc8::sce::tcp::kFoo``). We capture
        # the *last* segment of any scoped name so the evaluator can look
        # it up in the constant table — everything between the leading
        # ``::`` and the last ``::`` is namespace clutter we discard.
        had_scope = False
        if self.peek() and self.peek().kind == "SCOPE":  # type: ignore[union-attr]
            had_scope = True
            self.take()
        ident = self.expect("IDENT")
        parts.append(ident.text)
        scoped_idents.append(ident.text)

        while True:
            t = self.peek()
            if t and t.kind == "SCOPE":
                had_scope = True
                self.take()
                next_id = self.expect("IDENT")
                scoped_idents.append(next_id.text)
                continue
            break

        if had_scope:
            # ``::tc8::<ns>::kFoo`` → keep the immediate namespace so
            # the constant table lookup can disambiguate same-name
            # entries living in different namespaces.
            ns = scoped_idents[-2] if len(scoped_idents) >= 2 else ""
            base: Any = ScopedConst(name=scoped_idents[-1], namespace=ns)
        else:
            base = Ident(parts=tuple(parts))

        while True:
            t = self.peek()
            if t and t.kind == "DOT":
                self.take()
                next_id = self.expect("IDENT")
                if isinstance(base, Ident):
                    base = Ident(parts=base.parts + (next_id.text,))
                else:
                    # ``call(...).field`` and ``foo[i].field`` keep their
                    # left-hand result as the Member's target so the
                    # evaluator can dispatch on its runtime value (dict
                    # member lookup for sd_first_option_with_l4 results).
                    base = Member(target=base, name=next_id.text)
            elif t and t.kind == "LBRACK":
                self.take()
                idx_expr = self.or_expr()
                self.expect("RBRACK")
                if isinstance(base, Ident) and isinstance(idx_expr, IntLit):
                    base = Ident(parts=base.parts + (idx_expr.value,))
                else:
                    base = Opaque(note="dynamic-index")
            elif t and t.kind == "LPAREN":
                # Function or method call — opaque.
                self.take()
                args: list[Any] = []
                while self.peek() and self.peek().kind != "RPAREN":  # type: ignore[union-attr]
                    args.append(self.or_expr())
                    if not self.accept("COMMA"):
                        break
                self.expect("RPAREN")
                base = Call(target=base, args=args)
            else:
                break
        return base


def parse_cond(src: str) -> Any:
    """Tokenize + parse a SCXML cond into the small AST. Strips the leading
    ``cpp:`` prefix the harness puts on every SCE-evaluated cond."""
    s = src.strip()
    if s.startswith("cpp:"):
        s = s[4:]
    try:
        toks = tokenize(s)
        return Parser(toks).parse()
    except ValueError:
        return Opaque(note="parse-error")


# ---------------------------------------------------------------------------
# Kleene three-valued evaluator
# ---------------------------------------------------------------------------


# Sentinel for "we couldn't evaluate this sub-clause". The Kleene rules
# in _eval_bool let UNKNOWN drop out of AND chains when at least one
# concrete TRUE is present, and out of OR chains when a concrete TRUE/FALSE
# decides the result — so expected.X comparisons don't kill matches.
UNKNOWN = object()


# Map ``captured.NAME`` field aliases onto pcap-decoder field names. The
# generator can only see what decode_pcap.py writes; the SCXML grammar
# names the same observation under harness-side capture-struct fields.
CAPTURED_ALIASES = {
    "eth_src":          "src_mac",
    "eth_dst":          "dst_mac",
    "src_ip":           "src_ip",
    "dst_ip":           "dst_ip",
    "sender_hw":        "sender_mac",
    "target_hw":        "target_mac",
    "sender_proto_ip":  "sender_ip",
    "target_proto_ip":  "target_ip",
}

# TCP flag-name → bit, used to materialise an integer when SCXML asks
# ``captured.flags & 0xNN`` and the decoder stored flags as a "|"-joined
# string.
TCP_FLAG_BITS = {
    "FIN": 0x01, "SYN": 0x02, "RST": 0x04, "PSH": 0x08,
    "ACK": 0x10, "URG": 0x20, "ECE": 0x40, "CWR": 0x80,
}


def _flags_to_int(s: str) -> int:
    total = 0
    for f in s.split("|"):
        total |= TCP_FLAG_BITS.get(f.strip(), 0)
    return total


def _packet_view(packet: dict) -> dict:
    """Promote a few fields the SCXML uses by name. Direction / protocol
    aren't in fields{} but the cond grammar never references them, so we
    don't bother synthesizing those — wrong names cleanly resolve to
    UNKNOWN."""
    fields = dict(packet.get("fields") or {})
    # Eth + IP basics live on the top-level packet, not inside fields{}.
    for k in ("src_mac", "dst_mac", "src_ip", "dst_ip"):
        v = packet.get(k)
        if v is not None and k not in fields:
            fields[k] = v
    # Convenience aliases for SOME/IP-SD entry / option counts (the
    # SCXML uses ``captured.sd_entry_count`` / ``sd_option_count`` and
    # the per-option-type counts ``sd_ipv4_endpoint_count`` and
    # ``sd_ipv4_multicast_count`` as scalars; the decoder gives us the
    # underlying lists, so we derive the cardinalities here).
    sd_entries = fields.get("sd_entries")
    if isinstance(sd_entries, list):
        fields.setdefault("sd_entry_count", len(sd_entries))
        fields.setdefault("sd_entries_len", len(sd_entries))
    sd_options = fields.get("sd_options")
    if isinstance(sd_options, list):
        fields.setdefault("sd_option_count", len(sd_options))
        fields.setdefault(
            "sd_ipv4_endpoint_count",
            sum(1 for o in sd_options if (o.get("type") == 0x04)),
        )
        fields.setdefault(
            "sd_ipv4_multicast_count",
            sum(1 for o in sd_options if (o.get("type") == 0x14)),
        )
    # Materialise TCP flags as int when present as the "|"-joined string.
    flags = fields.get("flags")
    if isinstance(flags, str) and flags and flags != "—":
        fields["flags"] = _flags_to_int(flags)
    # DHCPv4 cookie / options-walk proxy: the decoder's option-53 parser
    # only populates ``dhcp_msg_type`` when the magic cookie matched
    # *and* a Message Type option was found, so its presence is the
    # generator-side proxy for the C++ ``magic_cookie_valid`` /
    # ``message_type_option_present`` flags. The decoder doesn't surface
    # ``op`` for DHCP frames yet, so we infer it from the port pair: a
    # source port 68 (BOOTPC) frame is a DUT-emitted BOOTREQUEST in
    # tc8-harness's topology (the tester server emul listens on 67).
    if "dhcp_msg_type" in fields and fields["dhcp_msg_type"] is not None:
        fields.setdefault("magic_cookie_valid", True)
        fields.setdefault("message_type_option_present", True)
        if "op" not in fields:
            sport = fields.get("src_port")
            if sport == 68:
                fields["op"] = 1  # BOOTREQUEST (client-emitted)
            elif sport == 67:
                fields["op"] = 2  # BOOTREPLY (server-emitted)
    # Stash the summary string so helpers can reach into it for fields
    # the decoder hasn't lifted yet (currently the TCP ``len=N`` tail).
    if "summary" in packet and "_summary" not in fields:
        fields["_summary"] = packet["summary"]
    return fields


def _resolve_ident(parts: tuple, packet_view: dict, expected: dict) -> Any:
    """Walk a dotted/indexed name through (captured / expected) namespaces.

    captured.X reads from ``packet_view`` via field aliases.
    expected.X reads from the per-case expected dict (smoke-test.sh
    fixture + DHCPv4 defaults + per-capture identity). Missing
    expected.X → UNKNOWN so the strict / lenient Kleene rules decide
    whether the surrounding cond can still settle.
    """
    if not parts:
        return UNKNOWN
    head = parts[0]
    if head == "expected":
        if len(parts) < 2 or not isinstance(parts[1], str):
            return UNKNOWN
        v = expected.get(parts[1], UNKNOWN)
        return UNKNOWN if v is UNKNOWN else v
    if head != "captured":
        return UNKNOWN
    if len(parts) < 2:
        return UNKNOWN
    name = parts[1]
    name = CAPTURED_ALIASES.get(name, name)
    cur: Any = packet_view.get(name, UNKNOWN)
    for seg in parts[2:]:
        if cur is UNKNOWN or cur is None:
            return UNKNOWN
        if isinstance(seg, int):
            if isinstance(cur, list) and 0 <= seg < len(cur):
                cur = cur[seg]
            else:
                return UNKNOWN
        elif isinstance(seg, str):
            if isinstance(cur, dict) and seg in cur:
                cur = cur[seg]
            else:
                return UNKNOWN
        else:
            return UNKNOWN
    return cur


def _eval(expr: Any, packet_view: dict, expected: dict, strict: bool) -> Any:
    """Returns int / bool / UNKNOWN.

    ``strict=False`` is the lenient pass-trigger mode: UNKNOWN clauses
    drop out of AND chains as long as at least one concrete TRUE clause
    decides the result. That lets ``service_id == expected.X`` act as a
    wildcard so the *other* discriminating clauses can still fire the
    transition.

    ``strict=True`` is the fail-trigger mode: UNKNOWN poisons AND/OR
    chains. A fail cond must evaluate to concrete TRUE end-to-end. This
    prevents the asymmetric ``X != expected.Y`` clause from rescuing a
    fail transition into a false positive when the actual ``expected.Y``
    value isn't loaded.
    """
    if isinstance(expr, IntLit):
        return expr.value
    if isinstance(expr, BoolLit):
        return expr.value
    if isinstance(expr, Ident):
        return _resolve_ident(expr.parts, packet_view, expected)
    if isinstance(expr, ScopedConst):
        table = scoped_consts()
        # Prefer the exact (namespace, name) match; fall back to file
        # scope when the namespace is empty (covers TCP constants that
        # live directly in ``tc8::sce::tcp`` but the loader records as
        # the immediate ``tcp`` namespace).
        v = table.get((expr.namespace, expr.name))
        if v is None:
            v = table.get(("", expr.name))
        if v is None:
            # Last-resort: bare-name match if there's exactly one
            # candidate. Keeps ``::tc8::sce::tcp::kFoo`` cond fragments
            # working for the historical TCP constants without
            # requiring the loader to capture the deeper namespace
            # chain.
            candidates = [val for (ns, nm), val in table.items() if nm == expr.name]
            if len(candidates) == 1:
                v = candidates[0]
        return v if v is not None else UNKNOWN
    if isinstance(expr, Call):
        return _eval_call(expr, packet_view, expected, strict)
    if isinstance(expr, Member):
        base = _eval(expr.target, packet_view, expected, strict)
        if base is UNKNOWN or base is None:
            return UNKNOWN
        if isinstance(base, dict):
            return base[expr.name] if expr.name in base else UNKNOWN
        # Anything else (int / bool / str) can't be member-accessed — the
        # cond is using a shape we don't model. Honest UNKNOWN.
        return UNKNOWN
    if isinstance(expr, (Opaque, InitList)):
        return UNKNOWN
    if isinstance(expr, UnOp):
        v = _eval(expr.operand, packet_view, expected, strict)
        if v is UNKNOWN:
            return UNKNOWN
        if expr.op == "not":
            return not bool(v)
        if expr.op == "-":
            return -v if isinstance(v, int) else UNKNOWN
        return UNKNOWN
    if isinstance(expr, BinOp):
        if expr.op == "and":
            return _bool_and(
                _eval(expr.lhs, packet_view, expected, strict),
                _eval(expr.rhs, packet_view, expected, strict),
                strict,
            )
        if expr.op == "or":
            return _bool_or(
                _eval(expr.lhs, packet_view, expected, strict),
                _eval(expr.rhs, packet_view, expected, strict),
                strict,
            )
        lhs = _eval(expr.lhs, packet_view, expected, strict)
        rhs = _eval(expr.rhs, packet_view, expected, strict)
        if lhs is UNKNOWN or rhs is UNKNOWN:
            return UNKNOWN
        try:
            if expr.op == "==": return lhs == rhs
            if expr.op == "!=": return lhs != rhs
            if expr.op == "<":  return lhs < rhs
            if expr.op == ">":  return lhs > rhs
            if expr.op == "<=": return lhs <= rhs
            if expr.op == ">=": return lhs >= rhs
            if expr.op == "&":  return lhs & rhs
            if expr.op == "|":  return lhs | rhs
            if expr.op == "+":  return lhs + rhs
            if expr.op == "-":  return lhs - rhs
            if expr.op == "*":  return lhs * rhs
            if expr.op == "/":  return lhs // rhs if rhs else UNKNOWN
        except (TypeError, ValueError):
            return UNKNOWN
    return UNKNOWN


# ---------------------------------------------------------------------------
# Captured method helpers
#
# The C++ helpers live in ``src/sce_integration/*_captured.h``. Each
# wraps a recurring 4-tuple + flag-mask check that recurs across many
# SCXML guards. Re-implementing the integer-typed ones here lets TCP
# cases with single-call conds still match.
# ---------------------------------------------------------------------------


# TCP flag bit positions (mirrors tcp_captured.h's hard-coded constants).
_TCP_FIN = 0x01
_TCP_SYN = 0x02
_TCP_RST = 0x04
_TCP_PSH = 0x08
_TCP_ACK = 0x10


def _packet_flags_int(view: dict) -> int | None:
    f = view.get("flags")
    if isinstance(f, int):
        return f
    return None


def _packet_payload_len(view: dict) -> int | None:
    """Decoder's TCP path stores ``len=N`` inside the summary string but
    doesn't yet surface ``payload_len`` as a numeric field. Fall back
    to parsing the summary's ``len=`` tail; absence is honest UNKNOWN."""
    pl = view.get("payload_len")
    if isinstance(pl, int):
        return pl
    summary = view.get("_summary", "")
    m = re.search(r"\blen=(\d+)\b", summary)
    return int(m.group(1)) if m else None


def _4tuple_match(view: dict, args: list[Any]) -> bool | None:
    """Common preamble for ``is_pure_dut_ack`` / ``is_dut_rst`` etc.
    Returns True / False / None — None means at least one operand
    couldn't be resolved (typically a stray UNKNOWN ScopedConst offset).
    """
    if len(args) < 4:
        return None
    e_dut_ip, e_tester_ip, e_src_port, e_dst_port = args[:4]
    if any(v is UNKNOWN for v in (e_dut_ip, e_tester_ip, e_src_port, e_dst_port)):
        return None
    sip = view.get("src_ip")
    dip = view.get("dst_ip")
    sp = view.get("src_port")
    dp = view.get("dst_port")
    if sip is None or dip is None or sp is None or dp is None:
        return False
    return (sip == e_dut_ip and dip == e_tester_ip
            and sp == e_src_port and dp == e_dst_port)


def _helper_is_pure_dut_ack(view, args) -> Any:
    base = _4tuple_match(view, args)
    if base is None: return UNKNOWN
    if not base: return False
    flags = _packet_flags_int(view)
    pl = _packet_payload_len(view)
    if flags is None: return UNKNOWN
    if (flags & _TCP_ACK) == 0: return False
    if (flags & (_TCP_SYN | _TCP_FIN | _TCP_RST)) != 0: return False
    if pl is not None and pl != 0: return False
    return True


def _helper_is_dut_fin_ack(view, args) -> Any:
    base = _4tuple_match(view, args)
    if base is None: return UNKNOWN
    if not base: return False
    flags = _packet_flags_int(view)
    if flags is None: return UNKNOWN
    if (flags & _TCP_FIN) == 0: return False
    if (flags & _TCP_ACK) == 0: return False
    if (flags & (_TCP_SYN | _TCP_RST)) != 0: return False
    return True


def _helper_is_dut_rst(view, args) -> Any:
    base = _4tuple_match(view, args)
    if base is None: return UNKNOWN
    if not base: return False
    flags = _packet_flags_int(view)
    if flags is None: return UNKNOWN
    return (flags & _TCP_RST) != 0


def _helper_is_dut_syn(view, args) -> Any:
    base = _4tuple_match(view, args)
    if base is None: return UNKNOWN
    if not base: return False
    flags = _packet_flags_int(view)
    if flags is None: return UNKNOWN
    if (flags & _TCP_SYN) == 0: return False
    if (flags & (_TCP_ACK | _TCP_FIN | _TCP_RST)) != 0: return False
    return True


def _helper_is_dut_data_segment(view, args) -> Any:
    base = _4tuple_match(view, args)
    if base is None: return UNKNOWN
    if not base: return False
    flags = _packet_flags_int(view)
    pl = _packet_payload_len(view)
    if flags is None: return UNKNOWN
    if (flags & _TCP_ACK) == 0: return False
    if (flags & (_TCP_SYN | _TCP_FIN | _TCP_RST)) != 0: return False
    if pl is None: return UNKNOWN
    return pl > 0


# DHCPv4 helpers (dhcpv4_captured.h). The decoder's option-53 walker
# only populates ``dhcp_msg_type`` when the magic-cookie matched and a
# Message Type option was found, so its presence on a packet is the
# generator-side proxy for the C++ ``magic_cookie_valid &&
# message_type_option_present`` short-circuit.


def _dhcp_msg_type(view: dict) -> int | None:
    mt = view.get("dhcp_msg_type")
    return mt if isinstance(mt, int) else None


def _is_dhcp_op_request(view: dict) -> bool | None:
    """``op == BOOTREQUEST (1)`` shared prefix of DUT-emit DHCP
    predicates. Returns UNKNOWN when the decoder didn't reach the
    BOOTP fixed header (truncated capture)."""
    op = view.get("op")
    return op == 1 if isinstance(op, int) else None


def _dhcp_emit_match(view: dict, mt_value: int) -> Any:
    if view.get("dhcp_msg_type") is None:
        return False  # not a DHCP packet, or cookie/options invalid
    op_ok = _is_dhcp_op_request(view)
    if op_ok is None:
        return UNKNOWN
    if not op_ok:
        return False
    return _dhcp_msg_type(view) == mt_value


def _helper_is_dhcp_discover(view, _args):   return _dhcp_emit_match(view, 1)
def _helper_is_dhcp_request(view, _args):    return _dhcp_emit_match(view, 3)
def _helper_is_dhcp_decline(view, _args):    return _dhcp_emit_match(view, 4)
def _helper_is_dhcp_release(view, _args):    return _dhcp_emit_match(view, 7)
def _helper_is_dhcp_inform(view, _args):     return _dhcp_emit_match(view, 8)


def _helper_has_message_type_option(view, _args) -> Any:
    return view.get("dhcp_msg_type") is not None


def _helper_source_ip_is_zero(view, _args) -> Any:
    s = view.get("src_ip")
    return s == "0.0.0.0" if isinstance(s, str) else UNKNOWN


def _helper_chaddr_matches_dut_mac(view, args) -> Any:
    if not args or args[0] is UNKNOWN:
        return UNKNOWN
    target = args[0]
    chaddr = view.get("chaddr")
    if not isinstance(chaddr, str) or not isinstance(target, str):
        return UNKNOWN
    return chaddr.lower() == target.lower()


# ARP helpers (arp_captured.h)
def _helper_is_arp_probe(view, _args) -> Any:
    # RFC 5227: opcode==1, sender_ip==0.0.0.0
    if view.get("opcode") == 1 and view.get("sender_ip") == "0.0.0.0":
        return True
    return False


def _helper_is_arp_reply(view, _args) -> Any:
    return view.get("opcode") == 2


def _helper_is_arp_announce(view, _args) -> Any:
    # opcode==1, sender_ip == target_ip (gratuitous)
    si = view.get("sender_ip")
    ti = view.get("target_ip")
    if view.get("opcode") == 1 and si == ti and si and si != "0.0.0.0":
        return True
    return False


def _helper_is_eth_broadcast(view, _args) -> Any:
    return view.get("dst_mac", "").lower() == "ff:ff:ff:ff:ff:ff"


def _helper_dst_ip_is_broadcast(view, _args) -> Any:
    return view.get("dst_ip") == "255.255.255.255"


def _helper_dst_ip_equals(view, args) -> Any:
    if not args or args[0] is UNKNOWN:
        return UNKNOWN
    target = args[0]
    if isinstance(target, int):
        target = _u32_be_to_dotted(target)
    return view.get("dst_ip") == target


def _helper_payload_bytes_eq(_view, _args) -> Any:
    # Decoder doesn't surface raw payload bytes; treat as UNKNOWN so
    # the surrounding cond (payload_len check etc.) can still settle.
    return UNKNOWN


def _helper_frame_delta_us(view, _args) -> Any:
    """Microseconds between this packet's pcap arrival timestamp and the
    most recent transition-firing packet's timestamp. Matches the C++
    ``Captured::frame_delta_us()`` semantics (delta from
    ``prev_observed_ts_us``, which advances only on dispatch-fire).

    Walker stashes ``_last_fired_ts_us`` (int or None) on the packet
    view before each evaluation. Returns 0 on the first transition (no
    prior fire) so a packet that's the FIRST observation can't
    accidentally satisfy a ``frame_delta_us() >= 1.95s`` cadence
    check."""
    ts = view.get("ts_us")
    last = view.get("_last_fired_ts_us")
    if not isinstance(ts, int):
        return UNKNOWN
    if not isinstance(last, int):
        return 0
    return ts - last


def _sd_option_with_l4(view: dict, args: list[Any]) -> dict | None | object:
    """Shared body of sd_first_option_with_l4 / sd_has_option_with_l4.
    Returns the matching option dict, ``None`` if no match, or UNKNOWN
    if the arguments / sd_options field are missing."""
    if len(args) < 2 or args[0] is UNKNOWN or args[1] is UNKNOWN:
        return UNKNOWN
    want_type, want_l4 = args[0], args[1]
    options = view.get("sd_options")
    if not isinstance(options, list):
        return UNKNOWN
    for o in options:
        if not isinstance(o, dict):
            continue
        if o.get("type") == want_type and o.get("l4_proto") == want_l4:
            return o
    return None


def _helper_sd_first_option_with_l4(view, args) -> Any:
    """Return the first decoded SD option dict whose ``type`` and
    ``l4_proto`` match the supplied filters. Member access on the
    returned dict reads the decoded fields directly: ``length`` (wire
    Length, 9 for IPv4 endpoint/multicast/sd-endpoint per
    PRS_SOMEIPSD §4.2.2), ``ipv4`` / ``port`` / ``l4_proto``,
    ``reserved1`` / ``reserved2`` (spec MUST be 0x00 — surfaced so
    conformance conds observe the wire byte rather than a synthesised
    value).

    Returns UNKNOWN when arguments or sd_options field are missing —
    keeps the surrounding cond honest under partial decoder output.
    """
    o = _sd_option_with_l4(view, args)
    if o is UNKNOWN:
        return UNKNOWN
    if o is None:
        # Option type / l4_proto filter matched no entry — every
        # subsequent ``.field`` access can't be satisfied, so UNKNOWN
        # rather than False keeps fail-trigger strict mode from
        # over-firing (the SCXML's matching pass clause for a different
        # SD frame should drive the real verdict).
        return UNKNOWN
    if not isinstance(o, dict):
        return UNKNOWN
    return o


def _helper_sd_has_option_with_l4(view, args) -> Any:
    o = _sd_option_with_l4(view, args)
    if o is UNKNOWN:
        return UNKNOWN
    return o is not None


CAPTURED_HELPERS = {
    # tcp_captured.h
    "is_pure_dut_ack":          _helper_is_pure_dut_ack,
    "is_dut_fin_ack":           _helper_is_dut_fin_ack,
    "is_dut_rst":               _helper_is_dut_rst,
    "is_dut_syn":               _helper_is_dut_syn,
    "is_dut_data_segment":      _helper_is_dut_data_segment,
    # arp_captured.h
    "is_arp_probe":             _helper_is_arp_probe,
    "is_arp_reply":             _helper_is_arp_reply,
    "is_arp_announce":          _helper_is_arp_announce,
    "is_eth_broadcast":         _helper_is_eth_broadcast,
    # dhcpv4_captured.h
    "is_dhcp_discover":         _helper_is_dhcp_discover,
    "is_dhcp_request":          _helper_is_dhcp_request,
    "is_dhcp_decline":          _helper_is_dhcp_decline,
    "is_dhcp_release":          _helper_is_dhcp_release,
    "is_dhcp_inform":           _helper_is_dhcp_inform,
    "has_message_type_option":  _helper_has_message_type_option,
    "source_ip_is_zero":        _helper_source_ip_is_zero,
    "chaddr_matches_dut_mac":   _helper_chaddr_matches_dut_mac,
    "dst_ip_is_broadcast":      _helper_dst_ip_is_broadcast,
    "dst_ip_equals":            _helper_dst_ip_equals,
    # someip_captured.h
    "payload_bytes_eq":         _helper_payload_bytes_eq,
    "sd_first_option_with_l4":  _helper_sd_first_option_with_l4,
    "sd_has_option_with_l4":    _helper_sd_has_option_with_l4,
    # cross-protocol
    "frame_delta_us":           _helper_frame_delta_us,
}


def _eval_call(call: Call, packet_view: dict, expected: dict, strict: bool) -> Any:
    """Resolve a ``captured.method(args)`` call. Only ``captured.NAME``
    targets are supported — anything else stays UNKNOWN."""
    target = call.target
    if not isinstance(target, Ident):
        return UNKNOWN
    if len(target.parts) != 2 or target.parts[0] != "captured":
        return UNKNOWN
    name = target.parts[1]
    helper = CAPTURED_HELPERS.get(name)
    if helper is None:
        return UNKNOWN
    args = [_eval(a, packet_view, expected, strict) for a in call.args]
    try:
        return helper(packet_view, args)
    except Exception:
        return UNKNOWN


def _bool_and(a: Any, b: Any, strict: bool) -> Any:
    if a is False or b is False:
        return False
    if strict:
        if a is UNKNOWN or b is UNKNOWN:
            return UNKNOWN
        return bool(a) and bool(b)
    # Lenient Kleene: UNKNOWN drops if something concrete decides.
    if a is UNKNOWN and b is UNKNOWN:
        return UNKNOWN
    if a is UNKNOWN:
        return bool(b)
    if b is UNKNOWN:
        return bool(a)
    return bool(a) and bool(b)


def _bool_or(a: Any, b: Any, strict: bool) -> Any:
    if a is True or b is True:
        return True
    if strict:
        if a is UNKNOWN or b is UNKNOWN:
            return UNKNOWN
        return bool(a) or bool(b)
    if a is UNKNOWN and b is UNKNOWN:
        return UNKNOWN
    if a is UNKNOWN:
        return UNKNOWN if not b else True
    if b is UNKNOWN:
        return UNKNOWN if not a else True
    return bool(a) or bool(b)


def cond_matches(expr: Any, packet_view: dict, expected: dict,
                 strict: bool = False) -> bool:
    """A transition matches when its cond evaluates to concrete TRUE.
    Caller controls strict vs lenient handling of UNKNOWN clauses."""
    return _eval(expr, packet_view, expected, strict) is True


# ---------------------------------------------------------------------------
# SCXML parser
# ---------------------------------------------------------------------------


SCXML_NS = "http://www.w3.org/2005/07/scxml"


@dataclass
class TransitionDef:
    event: str
    cond_src: str           # original cond source (for label cosmetics)
    cond_ast: Any           # parsed AST or Opaque
    target: str             # target state id


@dataclass
class StateDef:
    id: str
    phase_index: int        # 1-based, derived from order of non-final states
    is_final: bool
    final_kind: str         # "pass" / "fail" / "" (non-final)
    transitions: list[TransitionDef] = field(default_factory=list)


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag


SCE_USE_TAG = "use"
TESTS_DIR = REPO_ROOT / "tests"

# ``{$name}`` placeholders the SCE codegen substitutes when expanding a
# template. The consumer's ``<sce:use ... name="value" .../>`` attribute
# block provides the values — we mirror the substitution before parsing
# so cond strings tokenise cleanly.
_TEMPLATE_PARAM_RE = re.compile(r"\{\$([A-Za-z_][A-Za-z0-9_]*)\}")


def _load_template(rel_path: str, case_id: str, params: dict[str, str]):
    """Resolve a ``../_templates/foo.sce-template.xml`` path against the
    consumer case's directory and return the parsed ``<sce:template>``
    root element with ``{$name}`` placeholders substituted from the
    consumer's ``<sce:use>`` attribute block. Returns ``None`` if the
    file isn't there or substitution leaves an unresolved placeholder.
    """
    case_dir = TESTS_DIR / case_id.lower()
    tpath = (case_dir / rel_path).resolve()
    if not tpath.exists():
        return None
    try:
        raw = tpath.read_text(encoding="utf-8")
    except OSError:
        return None
    if params:
        def _sub(m: re.Match) -> str:
            name = m.group(1)
            if name in params:
                return params[name]
            # Leave unresolved placeholders alone so a missing param
            # surfaces visibly in the cond string; the cond parser
            # will degrade those clauses to Opaque.
            return m.group(0)
        raw = _TEMPLATE_PARAM_RE.sub(_sub, raw)
    try:
        return ET.fromstring(raw)
    except ET.ParseError:
        return None


def _parse_states_from(elem, states: list[StateDef], seen: set[str],
                       phase_counter: list[int]) -> None:
    """Append ``<state>`` and ``<final>`` direct children of ``elem`` to
    ``states``. Skips ids already in ``seen`` so a consumer SCXML's
    inline state (rare) wins over a template's same-id state."""
    for child in elem:
        tag = _strip_ns(child.tag)
        if tag == "state":
            sid = child.attrib.get("id", "")
            if sid in seen:
                continue
            phase_counter[0] += 1
            trs: list[TransitionDef] = []
            for tchild in child:
                if _strip_ns(tchild.tag) != "transition":
                    continue
                cond_src = tchild.attrib.get("cond", "")
                target = tchild.attrib.get("target", "")
                event = tchild.attrib.get("event", "")
                if not cond_src or not target:
                    # Deadline / no-cond transitions are time-driven —
                    # they never match against a packet, so we don't
                    # store them in the matcher's transition list.
                    continue
                trs.append(TransitionDef(
                    event=event,
                    cond_src=cond_src,
                    cond_ast=parse_cond(cond_src),
                    target=target,
                ))
            states.append(StateDef(
                id=sid, phase_index=phase_counter[0], is_final=False,
                final_kind="", transitions=trs,
            ))
            seen.add(sid)
        elif tag == "final":
            sid = child.attrib.get("id", "")
            if sid in seen:
                continue
            kind = "pass" if sid.lower() == "pass" else "fail" \
                if sid.lower().startswith("fail") else ""
            states.append(StateDef(
                id=sid, phase_index=0, is_final=True,
                final_kind=kind, transitions=[],
            ))
            seen.add(sid)


def parse_scxml(content: str, case_id: str = "") -> tuple[list[StateDef], str]:
    """Return (states-in-document-order, initial-state-id).

    Parses both ``<state>`` (with transitions) and ``<final>`` (verdict
    sinks) so the walker can detect when the SM has reached pass/fail.
    Resolves ``<sce:use template="..."/>`` directives by reading the
    referenced template and parsing its states as if they were inline
    children of the consumer SCXML — that's how the SCE codegen treats
    them (see tests/_templates/*.sce-template.xml for the body shared
    by Group C ARP / TCP basics / SOMEIPSRV OPTIONS family cases).
    """
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return [], ""

    template_root = None
    for child in root:
        if _strip_ns(child.tag) == SCE_USE_TAG:
            tpath = child.attrib.get("template", "")
            if tpath and case_id:
                # Every other attribute on <sce:use> is a substitution
                # value for the template's ``{$name}`` placeholders.
                params = {k: v for k, v in child.attrib.items() if k != "template"}
                template_root = _load_template(tpath, case_id, params)
                break

    initial = root.attrib.get("initial", "")
    states: list[StateDef] = []
    seen: set[str] = set()
    phase_counter = [0]
    _parse_states_from(root, states, seen, phase_counter)
    if template_root is not None:
        _parse_states_from(template_root, states, seen, phase_counter)
    return states, initial


# ---------------------------------------------------------------------------
# Cond-label cosmetics
# ---------------------------------------------------------------------------


def _short_cond(cond_src: str, limit: int = 140) -> str:
    """Tidy a cond for inline display: drop ``cpp:`` and ``captured.``
    noise, collapse whitespace, cap length."""
    s = cond_src.strip()
    if s.startswith("cpp:"):
        s = s[4:]
    s = re.sub(r"\s+", " ", s)
    s = s.replace("captured.", "")
    if len(s) > limit:
        s = s[: limit - 1].rstrip() + "…"
    return s


def _verdict_for_target(target: str, states_by_id: dict) -> str:
    """Return "pass" / "fail" / "" depending on what kind of state the
    target is."""
    st = states_by_id.get(target)
    if st and st.is_final:
        return st.final_kind
    return ""


# ---------------------------------------------------------------------------
# Walker — assigns role + label per packet idx
# ---------------------------------------------------------------------------


@dataclass
class AutoMessage:
    idx: int
    role: str
    label: str


def label_packets(
    states: list[StateDef], initial: str, packets: list[dict],
    expected: dict | None = None,
) -> list[AutoMessage]:
    expected = expected or {}
    if not states:
        return []
    states_by_id = {s.id: s for s in states}
    current_id = initial or (states[0].id if not states[0].is_final else "")
    if current_id and current_id not in states_by_id:
        current_id = states[0].id
    cur = states_by_id.get(current_id) if current_id else None
    final_outcome = ""  # "pass" / "fail" once the SM lands in a final

    msgs: list[AutoMessage] = []
    # Tracks the pcap-relative ts_us of the most recent packet that
    # caused the SM to fire a transition. Mirrors the C++
    # ``prev_observed_ts_us`` snapshot pattern (advances only on a
    # successful dispatch, NOT on every observed frame) so
    # ``frame_delta_us()`` cadence checks see the same baseline the
    # real test runner does.
    last_fired_ts_us: int | None = None

    for p in packets:
        idx = p.get("idx", 0)
        direction = p.get("direction", "other")
        view = _packet_view(p)
        # Surface the walker's last-fire baseline + this packet's ts to
        # the cond evaluator so ``captured.frame_delta_us()`` returns a
        # concrete delta. ``ts_us`` lifts the decoder's pcap-relative
        # field onto the view (the helper reads from view, not from p).
        view["_last_fired_ts_us"] = last_fired_ts_us
        if "ts_us" not in view and "ts_us" in p:
            view["ts_us"] = p["ts_us"]

        if final_outcome:
            # SM already at a final — post-verdict frames are teardown.
            msgs.append(AutoMessage(
                idx=idx, role="note",
                label=f"Post-{final_outcome} teardown (state machine already at final)",
            ))
            continue

        if cur is None or cur.is_final:
            msgs.append(AutoMessage(idx=idx, role="note", label="(no active state)"))
            continue

        # Try every non-deadline transition this state can fire. Order:
        # SCXML evaluation is document order — first matching transition
        # wins. We match the same way, with two guards:
        #   * Pass- and progress-target transitions only fire on
        #     DUT-emitted packets (the conds typically observe DUT
        #     behaviour and the ``expected.*`` constants we can't see
        #     often disambiguate DUT vs Tester frames that share
        #     captured-side fields).
        #   * Fail-target transitions require *strict* cond evaluation —
        #     UNKNOWN clauses don't get the lenient Kleene rescue. This
        #     stops ``captured.X != expected.Y`` from claiming a fail on
        #     every Tester frame just because we don't know the
        #     expected value.
        # Two-pass match.
        #
        # First pass: pass/progress transitions. Fire only on strict
        # cond TRUE (no UNKNOWN-rescue). The decoder's auto-detected
        # packet direction is sometimes wrong (the TCP active-OPEN path
        # where DUT initiates inverts the "first emitter is tester"
        # heuristic), so we *don't* gate on direction — the cond's own
        # ``captured.src_ip == expected.dut_iface_ip`` (or equivalent
        # service-id / 4-tuple check) provides the discriminator
        # already, and expected.X now resolves to real values.
        #
        # If any pass cond is *uncertain* (lenient TRUE but not strict
        # TRUE — i.e. an opaque helper or unloaded expected.X clause
        # was UNKNOWN-rescued), the real SCXML may have taken the pass
        # branch in the live run. Refuse to fall through to fail so a
        # passing test isn't auto-labelled as fail.
        matched: TransitionDef | None = None
        any_pass_uncertain = False
        for t in cur.transitions:
            verdict = _verdict_for_target(t.target, states_by_id)
            if verdict == "fail":
                continue
            strict_ok = cond_matches(t.cond_ast, view, expected, strict=True)
            lenient_ok = cond_matches(t.cond_ast, view, expected, strict=False)
            if lenient_ok and not strict_ok:
                any_pass_uncertain = True
            if strict_ok:
                matched = t
                break
        if matched is None and not any_pass_uncertain:
            for t in cur.transitions:
                verdict = _verdict_for_target(t.target, states_by_id)
                if verdict != "fail":
                    continue
                if cond_matches(t.cond_ast, view, expected, strict=True):
                    matched = t
                    break

        phase_tag = f"Phase {cur.phase_index} ({cur.id})"
        if matched is not None:
            # Advance the frame_delta_us baseline so the NEXT packet's
            # cadence check measures from this firing frame's ts.
            ts = view.get("ts_us")
            if isinstance(ts, int):
                last_fired_ts_us = ts
            verdict = _verdict_for_target(matched.target, states_by_id)
            cond_text = _short_cond(matched.cond_src)
            if verdict == "pass":
                role = "expected"
                label = (
                    f"{phase_tag} pass trigger — transitions to "
                    f"{matched.target}. Cond: {cond_text}"
                )
                msgs.append(AutoMessage(idx=idx, role=role, label=label))
                cur = states_by_id.get(matched.target, cur)
                if cur and cur.is_final:
                    final_outcome = cur.final_kind or "pass"
            elif verdict == "fail":
                role = "fail-trigger"
                label = (
                    f"{phase_tag} fail trigger — transitions to "
                    f"{matched.target}. Cond: {cond_text}"
                )
                msgs.append(AutoMessage(idx=idx, role=role, label=label))
                cur = states_by_id.get(matched.target, cur)
                if cur and cur.is_final:
                    final_outcome = cur.final_kind or "fail"
            else:
                # Forward transition into another non-final phase. A
                # fired cond means the packet matches a DUT-observable
                # criterion (src_ip / 4-tuple check) the SCXML treats
                # as expected behaviour, so label as "expected"
                # regardless of the pcap's auto-detected direction —
                # the cond is a more reliable discriminator than the
                # heuristic that flips on TCP active-OPEN.
                next_st = states_by_id.get(matched.target)
                next_label = matched.target if next_st else "?"
                label = (
                    f"{phase_tag} progress trigger — advances to "
                    f"{next_label}. Cond: {cond_text}"
                )
                msgs.append(AutoMessage(idx=idx, role="expected", label=label))
                cur = next_st or cur
            continue

        # No transition fired on this packet — classify by direction so
        # the reader still sees which phase the frame fell into.
        if direction == "tester_to_dut":
            msgs.append(AutoMessage(
                idx=idx, role="stimulus",
                label=f"{phase_tag} — Tester stimulus (no transition matched)",
            ))
        elif direction == "dut_to_tester":
            msgs.append(AutoMessage(
                idx=idx, role="note",
                label=f"{phase_tag} — DUT frame (no transition matched)",
            ))
        else:
            msgs.append(AutoMessage(
                idx=idx, role="note",
                label=f"{phase_tag} — observed frame",
            ))
    return msgs


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def _iter_case_ids(only: Iterable[str]) -> list[str]:
    only_set = {c.upper() for c in only}
    if only_set:
        return sorted(only_set)
    return sorted(p.stem for p in PCAP_DIR.glob("*.json"))


def generate_for(case_id: str) -> tuple[bool, str]:
    """Returns (wrote, message)."""
    cid = case_id.upper()
    case_path = CASES_DIR / f"{cid}.json"
    pcap_path = PCAP_DIR / f"{cid}.json"
    if not case_path.exists():
        return False, f"{cid}: case manifest missing"
    if not pcap_path.exists():
        return False, f"{cid}: pcap JSON missing"

    case_doc = json.loads(case_path.read_text(encoding="utf-8"))
    pcap_doc = json.loads(pcap_path.read_text(encoding="utf-8"))
    scxml_src = (case_doc.get("scxml") or {}).get("content") or ""
    if not scxml_src:
        return False, f"{cid}: no inlined SCXML"

    packets = pcap_doc.get("packets") or []
    if not packets:
        return False, f"{cid}: no packets"

    states, initial = parse_scxml(scxml_src, case_id=cid)
    expected = build_expected_dict(cid, pcap_doc)
    msgs = label_packets(states, initial, packets, expected)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / f"{cid}.json"
    out_path.write_text(json.dumps({
        "case_id": cid,
        "generator_version": GENERATOR_VERSION,
        "messages": [
            {"idx": m.idx, "role": m.role, "label": m.label}
            for m in msgs
        ],
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    return True, f"{cid}: wrote {len(msgs)} message(s)"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--only", action="append", default=[],
                    help="case_id (canonical) to generate; repeatable. "
                         "Default: every case with a pcap JSON.")
    ap.add_argument("--clean", action="store_true",
                    help="Remove OUT_DIR before generating (full runs only).")
    ap.add_argument("--cases-dir", type=Path, default=DEFAULT_CASES_DIR,
                    help="Directory of per-case manifests (default: main checkout).")
    ap.add_argument("--pcap-dir", type=Path, default=DEFAULT_PCAP_DIR,
                    help="Directory of decoded pcap JSON (default: site/src/data/pcap).")
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR,
                    help="Directory to write auto_messages JSON.")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    global CASES_DIR, PCAP_DIR, OUT_DIR
    CASES_DIR = args.cases_dir
    PCAP_DIR = args.pcap_dir
    OUT_DIR = args.out_dir

    if args.clean and not args.only:
        if OUT_DIR.exists():
            for old in OUT_DIR.glob("*.json"):
                old.unlink()

    ids = _iter_case_ids(args.only)
    if not ids:
        print("no cases to generate (pcap JSONs missing?)", file=sys.stderr)
        return 0

    wrote = 0
    skipped = 0
    for cid in ids:
        ok, message = generate_for(cid)
        if ok:
            wrote += 1
            if args.verbose:
                print(message)
        else:
            skipped += 1
            if args.verbose:
                print(message, file=sys.stderr)
    print(f"generated {wrote} message file(s); skipped {skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
