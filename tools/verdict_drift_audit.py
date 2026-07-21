#!/usr/bin/env python3
"""Enforce the conformance-verdict SSOT invariant.

Since the donedata-SSOT migration, each TC8 case declares its verdict exactly
once: in the SCXML `<final>`'s `<donedata><content>{"verdict":..,"reason":..}`
(or, for a template-based case, in the shared `.sce-template.xml` it binds via
`<sce:use>`). The generated SM stashes it and the runner reads it back
(`tc8::sce::verdictFromDonedata`, src/sce_integration/verdict.h). There is no
second declaration — the legacy per-case `verdictFor(State)` switch was retired.

This tool guards that single source. For every registered case it checks:

  MISSING_DONEDATA  no `<final>` carries a donedata verdict (the runner would
                    fall back to the "running" sentinel = fail-closed)
  BAD_CLASS         a donedata verdict class is not one of the canonical
                    conformance classes (pass / fail / inconclusive / error)
  NO_SCXML          the case header exists but its .scxml does not
  UNPARSED          the .scxml is not well-formed XML

Exit status is non-zero if any finding is present, so it can gate CI and the
pre-commit hook. Run with --summary for counts only.

Template resolution: a `<sce:use template=...>` case declares its finals once
in a shared template and binds per-case `{$fail_state}` / `{$fail_reason}` via
attributes; the audit substitutes them exactly as codegen does, so it sees the
same donedata the runner reads at runtime.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CASES_DIR = REPO / "src" / "sce_integration" / "include" / "sce_integration" / "cases"
TESTS_DIR = REPO / "tests"

SCE_NS = "http://sce.dev/ext"

# The classification policy (role -> class) and the valid class set are
# GENERATED from src/sce_integration/verdict_taxonomy.def — the single source,
# also #included by verdict.h — via tools/gen_verdict_taxonomy.py. See
# docs/verdict_policy.md §3. CI runs `gen_verdict_taxonomy.py --check`, so this
# import cannot drift from the C++ taxonomy or the bash smoke gate.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from verdict_taxonomy_gen import ROLE_POLICY, VALID_CLASSES  # noqa: E402

# Reasons are lower_snake_case identifiers (D-lite format check).
_REASON_RE = re.compile(r"^[a-z0-9_]+$")

# A verdict as (class, reason, role); reason/role are "" when absent.
Verdict = tuple[str, str, str]


@dataclass
class CaseReport:
    name: str
    findings: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# donedata extraction (inline + sce:template)
# --------------------------------------------------------------------------

_PARAM_RE = re.compile(r"\{\$(\w+)\}")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _subst(text: str, bindings: dict[str, str]) -> str:
    return _PARAM_RE.sub(lambda m: bindings.get(m.group(1), m.group(0)), text)


def _finals_from_root(root: ET.Element, bindings: dict[str, str]) -> dict[str, Verdict]:
    """Map final id (lowercased) -> verdict for every top-level `<final>`
    carrying a `<donedata><content>` JSON object, applying `{$param}` bindings."""
    out: dict[str, Verdict] = {}
    for fin in root.iter():
        if _local(fin.tag) != "final":
            continue
        fid = _subst(fin.get("id", ""), bindings)
        for dd in fin:
            if _local(dd.tag) != "donedata":
                continue
            for content in dd:
                if _local(content.tag) != "content":
                    continue
                raw = _subst((content.text or "").strip(), bindings)
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if obj.get("verdict") is None:
                    continue
                out[fid.lower()] = (
                    str(obj["verdict"]),
                    str(obj.get("reason", "")),
                    str(obj.get("role", "")),
                )
    return out


def extract_donedata(scxml_path: Path) -> dict[str, Verdict]:
    root = ET.parse(scxml_path).getroot()
    out = _finals_from_root(root, {})  # inline finals (direct cases)
    for el in root.iter():
        if _local(el.tag) == "use" and el.tag == f"{{{SCE_NS}}}use":
            tmpl_rel = el.get("template")
            if not tmpl_rel:
                continue
            tmpl_path = (scxml_path.parent / tmpl_rel).resolve()
            if not tmpl_path.is_file():
                continue
            bindings = {k: v for k, v in el.attrib.items() if k != "template"}
            troot = ET.parse(tmpl_path).getroot()
            out.update(_finals_from_root(troot, bindings))
    return out


# --------------------------------------------------------------------------
# audit
# --------------------------------------------------------------------------


def audit_case(name: str) -> CaseReport:
    rep = CaseReport(name=name)
    scxml_path = TESTS_DIR / name / f"{name}.scxml"
    if not scxml_path.is_file():
        rep.findings.append("NO_SCXML")
        return rep
    try:
        done = extract_donedata(scxml_path)
    except ET.ParseError as exc:
        rep.findings.append(f"UNPARSED: .scxml not parseable as XML ({exc})")
        return rep

    if not done:
        rep.findings.append("MISSING_DONEDATA: no <final> carries a donedata verdict")
        return rep

    for state, (cls, reason, role) in sorted(done.items()):
        if cls not in VALID_CLASSES:
            rep.findings.append(
                f"BAD_CLASS: final '{state}' verdict class '{cls}' not in {sorted(VALID_CLASSES)}"
            )
        # Policy enforcement: when a final declares a role, its class MUST be
        # that role's image under ROLE_POLICY (docs/verdict_policy.md §3).
        # Roleless finals are validity-checked only (back-compat during the
        # role rollout; the final rollout makes role mandatory for non-pass).
        if role:
            if role not in ROLE_POLICY:
                rep.findings.append(
                    f"BAD_ROLE: final '{state}' role '{role}' not in {sorted(ROLE_POLICY)}"
                )
            elif ROLE_POLICY[role] != cls:
                rep.findings.append(
                    f"ROLE_CLASS_MISMATCH: final '{state}' role '{role}' "
                    f"requires class '{ROLE_POLICY[role]}', got '{cls}'"
                )
        # D-lite: reason strings are lower_snake_case identifiers. Empty (pass)
        # and unsubstituted template params ({$...}) are exempt.
        if reason and "{$" not in reason and not _REASON_RE.match(reason):
            rep.findings.append(
                f"REASON_FORMAT: final '{state}' reason '{reason}' is not lower_snake_case"
            )
    return rep


def all_case_names() -> list[str]:
    """Registered cases only. A shared helper header (e.g.
    dhcpv4_router_option_egress_common.h, included by CM_05/_06) carries no
    `TC8_REGISTER_CASE` and is not a case, so it is excluded — the macro is the
    authoritative registration signal."""
    names = []
    for h in sorted(CASES_DIR.glob("*.h")):
        if h.name.startswith("_"):
            continue
        if "TC8_REGISTER_CASE" not in h.read_text(encoding="utf-8", errors="replace"):
            continue
        names.append(h.stem)
    return names


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("cases", nargs="*", help="case names to audit (default: all)")
    ap.add_argument("--summary", action="store_true", help="print only per-finding-type counts")
    args = ap.parse_args()

    reports = [audit_case(n) for n in (args.cases or all_case_names())]

    counts: dict[str, int] = {}
    for rep in reports:
        for f in rep.findings:
            kind = f.split(":")[0].split()[0]
            counts[kind] = counts.get(kind, 0) + 1
            if not args.summary:
                print(f"{rep.name}: {f}")

    clean = sum(1 for r in reports if not r.findings)
    print("=" * 60)
    print(f"cases audited: {len(reports)}")
    for kind in sorted(counts):
        print(f"  {kind}: {counts[kind]}")
    print(f"  CLEAN (donedata present, valid class): {clean}")
    print("=" * 60)

    return 1 if any(r.findings for r in reports) else 0


if __name__ == "__main__":
    sys.exit(main())
