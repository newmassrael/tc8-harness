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

OEM overlay (``SITE_EXTRA_CASE_ROOTS``):
    A ``:``-separated list of extra content roots (shell-``PATH`` style,
    mirroring the runtime ``TC8_EXTRA_CASE_DIRS`` seam). Unset ⇒ behaviour
    byte-identical to a public-only build. Each root is self-describing::

        <root>/inventory.json            # extra cases (bare list or {"cases":[…]})
                                         #   a case entry may carry an optional
                                         #   root-relative ``test_dir`` shown as
                                         #   its "Test directory" source link
        <root>/deprecated.json           # optional, same shape as docs/spec/
        <root>/inventory_overrides.json  # optional, {"overrides": {CID: {…}}}
        <root>/protocol_map.json         # optional, [{section_prefix, protocol_label}]
        <root>/traits/<cid>.h            # TestCaseTraits header
        <root>/scxml/<cid>.scxml         # case SCXML
        <root>/pcap/<CID>.json           # optional decoded-pcap JSON
        <root>/locales/<lang>/<CID>.json # optional per-locale override

    Extra cases are merged into the spec-order list and their artefacts
    resolve under the owning root; nothing from a root is ever written to
    the tracked public tree. Locale overrides are staged into the generated
    (git-ignored) ``site/src/data/extra_locales/`` so the build-time
    ``import.meta.glob`` in ``overrides.ts`` can still point at a fixed
    in-tree path (see that file).

Output:
    ``site/src/data/cases/<CASE_ID>.json`` — one file per case.
    ``site/src/data/index.json`` — summary list ordered by spec appearance.

Usage:
    python3 site/scripts/build_manifest.py            # all cases
    python3 site/scripts/build_manifest.py --only ARP_03
    SITE_EXTRA_CASE_ROOTS=/path/to/oem-root python3 site/scripts/build_manifest.py
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Callable, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
INVENTORY = REPO_ROOT / "docs" / "spec" / "case_inventory.json"
OVERRIDES = REPO_ROOT / "docs" / "spec" / "inventory_overrides.json"
DEPRECATED = REPO_ROOT / "docs" / "spec" / "deprecated_cases.json"
TESTS_DIR = REPO_ROOT / "tests"
TRAITS_DIR = REPO_ROOT / "src" / "sce_integration" / "cases"
PCAP_DIR = REPO_ROOT / "site" / "src" / "data" / "pcap"
OUT_DIR = REPO_ROOT / "site" / "src" / "data" / "cases"
INDEX_OUT = REPO_ROOT / "site" / "src" / "data" / "index.json"
EXTRA_LOCALES_OUT = REPO_ROOT / "site" / "src" / "data" / "extra_locales"


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


def _builtin_protocol(section: str) -> str | None:
    """Public spec-section → protocol label heuristic; None if unmatched."""
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
    return None


def _extra_protocol(section: str, extra_map: Sequence[tuple[str, str]]) -> str | None:
    """First OEM ``protocol_map`` label whose prefix matches; None if none."""
    return next(
        (label for prefix, label in extra_map if prefix and section.startswith(prefix)),
        None,
    )


def protocol_of(section: str, extra_map: Sequence[tuple[str, str]] = (),
                prefer_extra: bool = False) -> str:
    """Coarse protocol label for a spec section, resolved from two sources
    with an explicit precedence.

    ``extra_map`` carries the (section_prefix, protocol_label) pairs from OEM
    ``protocol_map.json`` roots. For an OEM overlay case (``prefer_extra``)
    the root's own map is tried BEFORE the built-in public heuristic, so an
    OEM chapter whose section overlaps a public prefix (e.g. an OEM
    SOME/IP-GEN chapter under ``5.1.5.x``) is labelled by the OEM map rather
    than bucketed into the public group. For a public case the built-in rules
    win and the map is only a fallback. Unmatched by both ⇒ "Other"."""
    builtin = _builtin_protocol(section)
    extra = _extra_protocol(section, extra_map)
    ordered = (extra, builtin) if prefer_extra else (builtin, extra)
    return next((label for label in ordered if label), "Other")


def spec_order_key(case: dict) -> tuple:
    return (case.get("split", ""), case.get("line", 0))


# ---------------------------------------------------------------------------
# Per-case artefact resolution (root-aware)
#
# A public case resolves its trait header, SCXML and pcap under the in-tree
# layout. An extra case carries its owning root in ``case["_root"]`` and
# resolves the same artefacts under that root's self-describing layout, so
# no OEM byte lands in the public tree.
# ---------------------------------------------------------------------------


def case_root(case: dict) -> Path | None:
    """Owning OEM root for an extra case, or None for a public case."""
    return case.get("_root")


def trait_path_for(case: dict) -> Path:
    lc = canonical(case["case_id"]).lower()
    root = case_root(case)
    return (root / "traits" / f"{lc}.h") if root else (TRAITS_DIR / f"{lc}.h")


def scxml_path_for(case: dict) -> Path:
    lc = canonical(case["case_id"]).lower()
    root = case_root(case)
    return (root / "scxml" / f"{lc}.scxml") if root else (TESTS_DIR / lc / f"{lc}.scxml")


def pcap_path_for(case: dict) -> Path:
    cid = canonical(case["case_id"])
    root = case_root(case)
    return (root / "pcap" / f"{cid}.json") if root else (PCAP_DIR / f"{cid}.json")


def overlay_test_dir(root: Path, case: dict) -> str | None:
    """Resolve an overlay case's optional, OEM-declared ``test_dir`` field.

    Unlike trait/scxml/pcap (built from the case_id, hence always under the
    root), ``test_dir`` is free-form inventory input, so it is confined to
    the root: an entry that resolves outside — an absolute path, or one
    escaping via ``..`` — is rejected to None rather than emitting a link
    that leaves the OEM's own tree. Returned normalised and root-relative,
    mirroring the sibling source fields."""
    declared = case.get("test_dir")
    if not declared:
        return None
    resolved = (root / declared).resolve()
    if not resolved.is_dir() or not resolved.is_relative_to(root):
        return None
    return str(resolved.relative_to(root))


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
        "protocol": protocol_of(section, ctx.get("protocol_map", ()),
                                prefer_extra=case_root(case) is not None),
        "section": section,
        "spec_order": case.get("_spec_order", 0),
        "status": "active",
        "expected": overrides.get("expected", True),
        "defer_reason": overrides.get("defer_reason", ""),
    }


def extract_trait(case: dict, ctx: dict) -> dict:
    info = parse_trait(trait_path_for(case))
    if not info or (not info.get("description") and not info.get("approach")
                    and not info.get("verdicts")):
        return {}
    return {"trait": info}


def extract_sources(case: dict, ctx: dict) -> dict:
    lc = canonical(case["case_id"]).lower()
    trait = trait_path_for(case)
    scxml = scxml_path_for(case)
    root = case_root(case)
    if root:
        # Paths are shown relative to the owning root; an OEM building from
        # its own repo points REPO_URL/REPO_REF (see lib/links.ts) at it.
        # The overlay layout splits trait/scxml across per-kind dirs, so
        # there is no implicit per-case test dir: an OEM declares one via an
        # optional root-relative ``test_dir`` on the inventory entry, confined
        # to the root by overlay_test_dir().
        return {
            "sources": {
                "trait_h": str(trait.relative_to(root)) if trait.exists() else None,
                "scxml": str(scxml.relative_to(root)) if scxml.exists() else None,
                "test_dir": overlay_test_dir(root, case),
            }
        }
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

    Files are written by ``tc8-harness decode-pcap`` (CI step, replaying each
    saved pcap through the harness's authoritative wire decoder) to
    ``site/src/data/pcap/<CASE_ID>.json``. The shape is documented in the
    site types (``PacketCapture``).
    """
    pcap_path = pcap_path_for(case)
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
    scxml_path = scxml_path_for(case)
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


# ---------------------------------------------------------------------------
# OEM overlay (SITE_EXTRA_CASE_ROOTS)
# ---------------------------------------------------------------------------


def discover_extra_roots() -> list[Path]:
    """Resolve ``SITE_EXTRA_CASE_ROOTS`` into existing directories.

    ``:``-separated, shell-``PATH`` style. Empty entries are ignored; a
    non-directory entry is warned and skipped rather than aborting the
    build, so a public build with the var unset is a plain no-op."""
    raw = os.environ.get("SITE_EXTRA_CASE_ROOTS", "")
    roots: list[Path] = []
    for part in raw.split(":"):
        part = part.strip()
        if not part:
            continue
        p = Path(part).expanduser().resolve()
        if not p.is_dir():
            print(f"warn: SITE_EXTRA_CASE_ROOTS entry is not a directory, skipping: {p}",
                  file=sys.stderr)
            continue
        roots.append(p)
    return roots


def load_root_inventory(root: Path) -> list[dict]:
    """Read a root's ``inventory.json`` and tag each case with its root.

    Accepts either a bare ``[…]`` list or the ``{"cases": […]}`` shape used
    by the public inventory, so an OEM can reuse either format."""
    inv_path = root / "inventory.json"
    if not inv_path.exists():
        print(f"warn: extra root has no inventory.json, skipping: {root}", file=sys.stderr)
        return []
    data = json.loads(inv_path.read_text(encoding="utf-8"))
    cases = data.get("cases", []) if isinstance(data, dict) else data
    for c in cases:
        c["_root"] = root
    return cases


def merge_root_metadata(roots: list[Path], overrides: dict,
                        deprecated_doc: dict) -> list[tuple[str, str]]:
    """Fold each root's optional overrides / deprecated into the in-memory
    public documents and return the accumulated protocol map.

    ``overrides`` / ``deprecated_doc`` are merged in place (main owns them);
    the protocol map is returned rather than stashed in a module global so
    ``protocol_of`` stays a pure function. Public keys are never removed;
    extra keys are additive (case_ids are required disjoint)."""
    protocol_map: list[tuple[str, str]] = []
    for root in roots:
        ov_path = root / "inventory_overrides.json"
        if ov_path.exists():
            extra = json.loads(ov_path.read_text(encoding="utf-8"))
            overrides.setdefault("overrides", {}).update(extra.get("overrides", {}))

        dep_path = root / "deprecated.json"
        if dep_path.exists():
            extra = json.loads(dep_path.read_text(encoding="utf-8"))
            deprecated_doc.setdefault("cases", []).extend(extra.get("cases", []))

        pm_path = root / "protocol_map.json"
        if pm_path.exists():
            for entry in json.loads(pm_path.read_text(encoding="utf-8")):
                protocol_map.append(
                    (entry["section_prefix"], entry["protocol_label"]))
    return protocol_map


def site_locales() -> list[str]:
    """Languages the site renders, derived from the tracked per-case locale
    dirs (``site/src/locales/cases/<lang>/``).

    This is the filesystem SSOT for supported languages: the TS/JS side
    (astro.config.mjs, i18n.ts, overrides.ts) must hard-code the same set
    because Vite's ``import.meta.glob`` needs literal paths, but this script
    cannot import those, so it reads the dirs instead of adding another
    hand-maintained copy of the list."""
    base = REPO_ROOT / "site" / "src" / "locales" / "cases"
    if not base.is_dir():
        return []
    return sorted(d.name for d in base.iterdir() if d.is_dir())


def stage_extra_locales(roots: list[Path]) -> None:
    """Copy each root's ``locales/<lang>/*.json`` into the generated
    (git-ignored) staging dir that ``overrides.ts`` globs at build time.

    The staging dir is wiped and recreated on every run so a removed or
    changed root set can never leave a stale override behind; the ``en``/
    ``ko`` dirs are always created (empty when the var is unset) so the
    build-time glob always resolves a real path."""
    langs = site_locales()
    for lang in langs:
        d = EXTRA_LOCALES_OUT / lang
        d.mkdir(parents=True, exist_ok=True)
        for old in d.glob("*.json"):
            old.unlink()
    for root in roots:
        loc_dir = root / "locales"
        for lang in langs:
            src = loc_dir / lang
            if not src.is_dir():
                continue
            for f in src.glob("*.json"):
                (EXTRA_LOCALES_OUT / lang / f.name).write_text(
                    f.read_text(encoding="utf-8"), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--only", action="append", default=[],
                    help="case_id (canonical) to build; repeatable. Default: all.")
    args = ap.parse_args(argv)

    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    overrides = json.loads(OVERRIDES.read_text(encoding="utf-8"))
    deprecated_doc = json.loads(DEPRECATED.read_text(encoding="utf-8"))

    # OEM overlay: discover extra roots, fold their metadata into the public
    # documents, stage their locales. All no-ops when the var is unset, so a
    # public build is byte-identical.
    extra_roots = discover_extra_roots()
    protocol_map = merge_root_metadata(extra_roots, overrides, deprecated_doc)
    stage_extra_locales(extra_roots)
    ctx = {"overrides": overrides, "protocol_map": protocol_map}

    # Extra case_ids must be disjoint from every public id — active *and*
    # deprecated — so an OEM case can never silently shadow a retired one.
    public_cases = list(inventory["cases"])
    seen_ids = {canonical(c["case_id"]) for c in public_cases}
    for entry in deprecated_doc.get("cases", []):
        seen_ids.add(canonical(entry if isinstance(entry, str) else entry["case_id"]))

    extra_cases: list[dict] = []
    for root in extra_roots:
        for c in load_root_inventory(root):
            cid = canonical(c["case_id"])
            if cid in seen_ids:
                raise SystemExit(
                    f"error: extra case_id {cid} from {root} collides with an "
                    "existing case (extra ids must be disjoint)")
            seen_ids.add(cid)
            extra_cases.append(c)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    # A full build owns the whole directory: wipe it first so a case removed
    # from the inventory — or an OEM case left behind after SITE_EXTRA_CASE_ROOTS
    # changes between local runs — cannot linger and be re-globbed into the
    # index. An ``--only`` build is incremental and must preserve its siblings.
    if not args.only:
        for old in OUT_DIR.glob("*.json"):
            old.unlink()

    cases_in_spec_order = sorted(public_cases + extra_cases, key=spec_order_key)
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
            "protocol": protocol_of(section, protocol_map),
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
