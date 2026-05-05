#!/usr/bin/env python3
"""Build per-case JSON manifests for the TC8 harness site.

Structured as a chain of independent extractors. Each returns a dict that
gets merged into the case record. To add a new section to the detail page:
add an extractor here, a component in ``site/src/components/sections/``,
and an entry in ``site/src/lib/sections.ts``.

The site's user-facing content is sourced from artefacts authored in this
repo — trait headers (``src/sce_integration/cases/<case>.h``), SCXML, test
runs — never from the upstream TC8 PDF spec body. Only factual metadata
(case ID, section number) is taken from the spec inventory.

Output:
    ``site/src/data/cases/<CASE_ID>.json`` — one file per case.
    ``site/src/data/index.json`` — summary list ordered by spec appearance.

Usage:
    python3 site/scripts/build_manifest.py            # all cases
    python3 site/scripts/build_manifest.py --only ARP_03
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Callable


REPO_ROOT = Path(__file__).resolve().parents[2]
INVENTORY = REPO_ROOT / "doc" / "spec" / "case_inventory.json"
OVERRIDES = REPO_ROOT / "doc" / "spec" / "inventory_overrides.json"
DEPRECATED = REPO_ROOT / "doc" / "spec" / "deprecated_cases.json"
TESTS_DIR = REPO_ROOT / "tests"
TRAITS_DIR = REPO_ROOT / "src" / "sce_integration" / "cases"
OUT_DIR = REPO_ROOT / "site" / "src" / "data" / "cases"
INDEX_OUT = REPO_ROOT / "site" / "src" / "data" / "index.json"


def section_hint_for(case_id: str) -> str:
    """Derive a coarse spec-section number from a deprecated case_id prefix.
    Used when the deletion table doesn't carry the original subsection."""
    cid = case_id.upper()
    if cid.startswith("ARP_"):
        return "4.2"
    if cid.startswith("ICMPV4_"):
        return "4.3"
    if cid.startswith("IPV4_AUTOCONF_"):
        return "4.5"
    if cid.startswith("IPV4_"):
        return "4.4"
    if cid.startswith("UDP_"):
        return "4.6"
    if cid.startswith("DHCPV4_"):
        return "4.7"
    if cid.startswith("TCP_"):
        return "4.8"
    if cid.startswith("SOMEIPSRV_"):
        return "5.1.5"
    if cid.startswith("SOMEIP_ETS_"):
        return "5.1.6"
    return ""


# ---------------------------------------------------------------------------
# Trait header parser
# ---------------------------------------------------------------------------


STRING_LITERAL_RE = re.compile(r'"((?:[^"\\]|\\.)*)"', re.DOTALL)


def _decode_cpp_string(s: str) -> str:
    """Decode C++ escape sequences in an extracted string literal."""
    return (s.replace(r'\n', '\n')
             .replace(r'\t', '\t')
             .replace(r'\"', '"')
             .replace(r'\\', '\\'))


def _extract_string_constant(text: str, name: str) -> str:
    """Find ``static constexpr std::string_view <name> = "...";`` and return
    the concatenated value of its string literal RHS."""
    pattern = rf"\b{re.escape(name)}\s*=\s*([^;]+?);"
    m = re.search(pattern, text, re.DOTALL)
    if not m:
        return ""
    parts = STRING_LITERAL_RE.findall(m.group(1))
    return _decode_cpp_string("".join(parts)).strip()


COMMENT_LINE_RE = re.compile(r"^\s*//\s?(.*?)\s*$")


def _find_class_body_start(text: str) -> int:
    """Return the index just past the trait class opener brace, or -1.

    Walks chars from ``struct TestCaseTraits`` onward, tracking ``<>``
    depth so braces inside template arguments (e.g. ``std::uint8_t{0}``
    in a base spec) are ignored. The first ``{`` at angle depth 0 is the
    class body opener.
    """
    m = re.search(r"\bstruct\s+TestCaseTraits\b", text)
    if not m:
        return -1
    i = m.end()
    n = len(text)
    angle = 0
    while i < n:
        ch = text[i]
        if ch == '<':
            angle += 1
        elif ch == '>':
            if angle > 0:
                angle -= 1
        elif ch == '{' and angle == 0:
            return i + 1
        elif ch == ';' and angle == 0:
            return -1
        i += 1
    return -1


def _extract_class_level_text(text: str) -> str:
    """Return the trait class body with every nested ``{...}`` block elided.

    Walker skips strings and comments so braces inside literals don't
    desync the depth counter, then drops everything inside function
    bodies while keeping declarations and comments at class top level.
    """
    start = _find_class_body_start(text)
    if start < 0:
        return ""

    out: list[str] = []
    depth = 0
    i = start
    n = len(text)
    while i < n:
        if text[i:i+2] == "//":
            eol = text.find("\n", i)
            eol = n if eol == -1 else eol
            if depth == 0:
                out.append(text[i:eol])
            i = eol
            continue
        if text[i:i+2] == "/*":
            j = text.find("*/", i + 2)
            j = n if j == -1 else j
            if depth == 0:
                out.append(text[i:j + 2])
            i = j + 2
            continue
        ch = text[i]
        if ch == '"':
            j = i + 1
            while j < n and text[j] != '"':
                if text[j] == "\\":
                    j += 1
                j += 1
            i = j + 1
            continue
        if ch == "{":
            depth += 1
            i += 1
            continue
        if ch == "}":
            if depth == 0:
                break
            depth -= 1
            i += 1
            continue
        if ch == "\n" and depth == 0:
            out.append("\n")
        i += 1
    return "".join(out)


def _collect_comment_blocks(class_text: str) -> list[str]:
    """Group consecutive ``//`` lines into blocks, drop single-line blocks."""
    blocks: list[str] = []
    current: list[str] = []
    for ln in class_text.splitlines():
        cm = COMMENT_LINE_RE.match(ln)
        if cm:
            current.append(cm.group(1))
        elif current:
            if len(current) >= 2:
                blocks.append("\n".join(current).rstrip())
            current = []
    if current and len(current) >= 2:
        blocks.append("\n".join(current).rstrip())
    return blocks


def _extract_approach(text: str) -> str:
    blocks = _collect_comment_blocks(_extract_class_level_text(text))
    return "\n\n".join(blocks).strip()


VERDICT_CASE_RE = re.compile(
    r'case\s+State::(?P<state>\w+)\s*:\s*return\s+"(?P<verdict>[^"]*)"\s*;',
)


def _extract_verdict_map(text: str) -> list[dict]:
    """Pull ``case State::X: return "Y";`` pairs from the verdictFor body."""
    body_match = re.search(
        r"verdictFor\s*\([^)]*\)\s*(?:->\s*\w[\w:<>]*\s*)?\{(?P<body>.*?)\n\s*\}",
        text, re.DOTALL,
    )
    if not body_match:
        return []
    body = body_match.group("body")
    return [
        {"state": m.group("state"), "verdict": m.group("verdict")}
        for m in VERDICT_CASE_RE.finditer(body)
    ]


def _extract_bpf_group(text: str) -> str:
    """Pull the BpfGroup enum value, if declared."""
    m = re.search(r"kBpfGroup\s*=\s*::tc8::BpfGroup::(\w+)", text)
    return m.group(1) if m else ""


def parse_trait(path: Path) -> dict:
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")
    return {
        "description": _extract_string_constant(text, "kDescription"),
        "approach": _extract_approach(text),
        "verdicts": _extract_verdict_map(text),
        "bpf_group": _extract_bpf_group(text),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def canonical(case_id: str) -> str:
    return case_id.upper()


def category_of(case_id: str) -> str:
    return re.sub(r"_\d+$", "", canonical(case_id))


def protocol_of(section: str) -> str:
    if section.startswith("4.2"):
        return "ARP"
    if section.startswith("4.3"):
        return "ICMPv4"
    if section.startswith("4.4"):
        return "IPv4"
    if section.startswith("4.5"):
        return "IPv4 Link-Local"
    if section.startswith("4.6"):
        return "UDP"
    if section.startswith("4.7"):
        return "DHCPv4"
    if section.startswith("4.8"):
        return "TCP"
    if section.startswith("5.1.4") or section.startswith("5.1.5"):
        return "SOME/IP-SRV"
    if section.startswith("5.1.6"):
        return "SOME/IP-ETS"
    return "Other"


def spec_order_key(case: dict) -> tuple:
    return (case.get("split", ""), case.get("line", 0))


# ---------------------------------------------------------------------------
# Extractors
# ---------------------------------------------------------------------------


def extract_header(case: dict, ctx: dict) -> dict:
    cid = canonical(case["case_id"])
    section = case.get("section", "")
    overrides = ctx["overrides"].get("overrides", {}).get(cid, {})
    return {
        "case_id": cid,
        "case_id_raw": case["case_id"],
        "category": category_of(cid),
        "protocol": protocol_of(section),
        "section": section,
        "spec_order": case.get("_spec_order", 0),
        "status": "active",
        "expected": overrides.get("expected", True),
        "defer_reason": overrides.get("defer_reason", ""),
    }


def extract_trait(case: dict, ctx: dict) -> dict:
    cid = canonical(case["case_id"])
    trait_path = TRAITS_DIR / f"{cid.lower()}.h"
    info = parse_trait(trait_path)
    if not info or (not info.get("description") and not info.get("approach")
                    and not info.get("verdicts")):
        return {}
    return {"trait": info}


def extract_sources(case: dict, ctx: dict) -> dict:
    cid = canonical(case["case_id"])
    lc = cid.lower()
    trait = TRAITS_DIR / f"{lc}.h"
    scxml = TESTS_DIR / lc / f"{lc}.scxml"
    return {
        "sources": {
            "trait_h": str(trait.relative_to(REPO_ROOT)) if trait.exists() else None,
            "scxml": str(scxml.relative_to(REPO_ROOT)) if scxml.exists() else None,
            "test_dir": f"tests/{lc}" if (TESTS_DIR / lc).exists() else None,
        }
    }


def extract_runs(case: dict, ctx: dict) -> dict:
    return {}


def extract_pcap(case: dict, ctx: dict) -> dict:
    """Inline the per-case packet capture JSON if one exists.

    Files are written by ``scripts/decode_pcap.py`` (CI step) to
    ``site/src/data/pcap/<CASE_ID>.json``. The shape is documented in the
    site types (``PacketCapture``).
    """
    cid = canonical(case["case_id"])
    pcap_path = REPO_ROOT / "site" / "src" / "data" / "pcap" / f"{cid}.json"
    if not pcap_path.exists():
        return {}
    try:
        data = json.loads(pcap_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"warn: {pcap_path} malformed: {exc}", file=sys.stderr)
        return {}
    return {"pcap": data}


def extract_messages(case: dict, ctx: dict) -> dict:
    """Important-message annotations live in the per-locale override files
    (``site/src/locales/cases/<lang>/<CASE_ID>.json``) and are read by the
    site at render time, so nothing is embedded in the manifest here."""
    return {}


def extract_scxml(case: dict, ctx: dict) -> dict:
    """Inline the raw SCXML so the case page is self-contained.

    The ScxmlSection component renders this with build-time syntax
    highlighting via Astro's ``<Code>`` (shiki). Phase 7 will optionally
    add a ``diagram`` field with a Mermaid translation.
    """
    cid = canonical(case["case_id"])
    lc = cid.lower()
    scxml_path = TESTS_DIR / lc / f"{lc}.scxml"
    if not scxml_path.exists():
        return {}
    return {"scxml": {"content": scxml_path.read_text(encoding="utf-8")}}


EXTRACTORS: list[Callable[[dict, dict], dict]] = [
    extract_header,
    extract_trait,
    extract_sources,
    extract_runs,
    extract_pcap,
    extract_messages,
    extract_scxml,
]


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def build_one(case: dict, ctx: dict) -> dict:
    record: dict = {}
    for fn in EXTRACTORS:
        record.update(fn(case, ctx))
    return record


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--only", action="append", default=[],
                    help="case_id (canonical) to build; repeatable. Default: all.")
    ap.add_argument("--clean", action="store_true",
                    help="Wipe OUT_DIR before writing (full builds only).")
    args = ap.parse_args(argv)

    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    overrides = json.loads(OVERRIDES.read_text(encoding="utf-8"))
    deprecated_doc = json.loads(DEPRECATED.read_text(encoding="utf-8"))
    ctx = {"overrides": overrides}

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    if args.clean and not args.only:
        for old in OUT_DIR.glob("*.json"):
            old.unlink()

    cases_in_spec_order = sorted(inventory["cases"], key=spec_order_key)
    for i, case in enumerate(cases_in_spec_order):
        case["_spec_order"] = i

    only = {c.upper() for c in args.only}
    n_written = 0
    for raw in cases_in_spec_order:
        cid = canonical(raw["case_id"])
        if only and cid not in only:
            continue
        record = build_one(raw, ctx)
        out_path = OUT_DIR / f"{cid}.json"
        out_path.write_text(json.dumps(record, indent=2, ensure_ascii=False),
                            encoding="utf-8")
        n_written += 1

    # Deprecated cases get placeholder records — Header section renders the
    # status badge + reason; data-bearing sections (trait, scxml, pcap)
    # auto-skip via the `requires` predicates in lib/sections.ts.
    active_ids = {canonical(c["case_id"]) for c in cases_in_spec_order}
    default_reason = deprecated_doc.get("default_reason", "Deprecated")

    # Index actives by case-id prefix → sorted (numeric_suffix, spec_order)
    # so a deprecated case can slot in next to its numeric neighbours
    # rather than collecting at the tail of the index.
    from collections import defaultdict
    PREFIX_RE = re.compile(r"_(\d+)$")
    prefix_actives: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for c in cases_in_spec_order:
        cid = canonical(c["case_id"])
        m = PREFIX_RE.search(cid)
        if not m:
            continue
        prefix = cid[: m.start()]
        prefix_actives[prefix].append((int(m.group(1)), c["_spec_order"]))
    for p in prefix_actives:
        prefix_actives[p].sort()

    # Anchor table for prefixes that are entirely deprecated (no active
    # case carries the same id-prefix). Keys are spec section prefixes
    # ("4.8", "4.8.6", etc.); value is the spec_order of the first
    # active case whose section starts that way.
    section_anchors: dict[str, int] = {}
    for c in cases_in_spec_order:
        sec = c.get("section", "")
        for plen in (3, 5, 7):
            key = sec[:plen]
            if key and key not in section_anchors:
                section_anchors[key] = c["_spec_order"]

    def deprecated_spec_order(cid: str, section_hint: str) -> float:
        m = PREFIX_RE.search(cid)
        if not m:
            return 1 << 20
        prefix, suffix = cid[: m.start()], int(m.group(1))
        actives = prefix_actives.get(prefix, [])
        bump = suffix * 0.001
        if actives:
            ts = next((order for s, order in actives if s > suffix), None)
            if ts is not None:
                return ts - 1.0 + bump
            return actives[-1][1] + bump
        for plen in (7, 5, 3):
            key = section_hint[:plen]
            if key in section_anchors:
                return section_anchors[key] - 1.0 + bump
        return 1 << 20

    for entry in deprecated_doc.get("cases", []):
        if isinstance(entry, str):
            cid, reason = canonical(entry), default_reason
        else:
            cid = canonical(entry["case_id"])
            reason = entry.get("reason", default_reason)
        if only and cid not in only:
            continue
        if cid in active_ids:
            print(f"warn: {cid} listed deprecated but is in active inventory; skipping",
                  file=sys.stderr)
            continue
        section = section_hint_for(cid)
        record = {
            "case_id": cid,
            "case_id_raw": cid,
            "category": category_of(cid),
            "protocol": protocol_of(section),
            "section": section,
            "spec_order": deprecated_spec_order(cid, section),
            "status": "deprecated",
            "expected": False,
            "defer_reason": reason,
        }
        out_path = OUT_DIR / f"{cid}.json"
        out_path.write_text(json.dumps(record, indent=2, ensure_ascii=False),
                            encoding="utf-8")
        n_written += 1

    index_records: list[dict] = []
    for path in OUT_DIR.glob("*.json"):
        rec = json.loads(path.read_text(encoding="utf-8"))
        index_records.append(rec)
    index_records.sort(key=lambda r: r.get("spec_order", 1 << 30))

    index_entries = [
        {
            "case_id": rec["case_id"],
            "category": rec["category"],
            "protocol": rec["protocol"],
            "section": rec["section"],
            "status": rec["status"],
            "expected": rec["expected"],
            "title": rec.get("trait", {}).get("description", ""),
        }
        for rec in index_records
    ]
    INDEX_OUT.write_text(json.dumps({
        "schema_version": 1,
        "case_count": len(index_entries),
        "cases": index_entries,
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {n_written} case file(s); index has {len(index_entries)} entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
