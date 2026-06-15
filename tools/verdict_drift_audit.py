#!/usr/bin/env python3
"""Audit agreement between a case's two verdict encodings.

The conformance verdict for each TC8 case is currently declared in two
places (debt B, project_conformance_verdict_model):

  1. C++ trait  : `TestCaseTraits<SM>::verdictFor(State)` in
                  src/sce_integration/cases/<case>.h — a switch from the
                  generated State enum to "<class>" or "<class>:<reason>".
  2. SCXML spec : `<final id="..."><donedata><content>{"verdict":..,
                  "reason":..}</content>` in tests/<case>/<case>.scxml.

Encoding (1) is the live source today (test_runner.h calls verdictFor);
encoding (2) is currently dead. The migration makes the SCXML donedata the
single source of truth (W3C SCXML 5.5) and retires verdictFor. For that to
be sound, the two encodings must agree wherever both exist, and every case
must eventually carry donedata covering all its final states.

This tool reports, per case:

  MISSING_DONEDATA  case has verdictFor but the .scxml has no donedata
                    (must be authored before donedata can become SSOT)
  DRIFT             a final state's verdict differs between the two
  FINAL_NO_VERDICT  .scxml final has donedata but verdictFor lacks the state
  VERDICT_NO_FINAL  verdictFor names a (non-default) state with no matching
                    .scxml final id (possible rename / stale entry)
  UNPARSED          verdictFor body could not be parsed (manual review)

Exit status is non-zero if any DRIFT / UNPARSED / FINAL_NO_VERDICT /
VERDICT_NO_FINAL is found (these block a sound migration); MISSING_DONEDATA
alone does not fail the run (it is the expected pre-migration backlog) unless
--strict is passed.

Normalisation: the generated State enum capitalises the first letter of the
SCXML state id (`fail_wrap_to_zero` -> `State::Fail_wrap_to_zero`), so the
join key is the lowercased enum name == the final id. verdictFor's
`"<class>:<reason>"` maps to donedata `{"verdict":class,"reason":reason}`;
a bare `"<class>"` maps to `{"verdict":class}` with no reason. The default
arm (`return "running"`) is the non-final sentinel and is excluded.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

SCE_NS = "http://sce.dev/ext"

REPO = Path(__file__).resolve().parent.parent
CASES_DIR = REPO / "src" / "sce_integration" / "cases"
TESTS_DIR = REPO / "tests"

# A verdict as (class, reason); reason is "" when absent.
Verdict = tuple[str, str]


@dataclass
class CaseReport:
    name: str
    findings: list[str] = field(default_factory=list)
    has_scxml: bool = True
    has_donedata: bool = False


def _verdict_from_trait_literal(lit: str) -> Verdict:
    """`"fail:reason"` -> ("fail", "reason"); `"pass"` -> ("pass", "")."""
    cls, _, reason = lit.partition(":")
    return cls, reason


def parse_verdict_for(header_text: str) -> dict[str, Verdict] | None:
    """Map lowercased State name -> verdict from a verdictFor switch.

    Returns None if the verdictFor body can't be located/parsed. Handles
    case-fallthrough (several `case State::X:` sharing one return).
    """
    m = re.search(r"verdictFor\s*\(", header_text)
    if not m:
        return None
    # Find the function body: first '{' after the signature, matched to its '}'.
    brace_start = header_text.find("{", m.end())
    if brace_start < 0:
        return None
    depth = 0
    i = brace_start
    while i < len(header_text):
        c = header_text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    if depth != 0:
        return None
    body = header_text[brace_start : i + 1]

    # Token stream of `case State::Name:`, `default:`, and `return "...";`,
    # in source order, so fallthrough assigns a return to all pending labels.
    token_re = re.compile(
        r'case\s+State::(?P<state>\w+)\s*:'
        r'|(?P<default>default\s*:)'
        r'|return\s+"(?P<ret>[^"]*)"\s*;'
    )
    mapping: dict[str, Verdict] = {}
    pending: list[str] = []  # state names awaiting a return (None == default)
    saw_default_pending = False
    for tok in token_re.finditer(body):
        if tok.group("state"):
            pending.append(tok.group("state"))
        elif tok.group("default"):
            saw_default_pending = True
        elif tok.group("ret") is not None:
            ret = tok.group("ret")
            for st in pending:
                if ret != "running":  # "running" is the non-final sentinel
                    mapping[st.lower()] = _verdict_from_trait_literal(ret)
            pending.clear()
            saw_default_pending = False
    return mapping


_PARAM_RE = re.compile(r"\{\$(\w+)\}")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _subst(text: str, bindings: dict[str, str]) -> str:
    return _PARAM_RE.sub(lambda m: bindings.get(m.group(1), m.group(0)), text)


def _finals_from_root(root: ET.Element, bindings: dict[str, str]) -> dict[str, Verdict]:
    """Walk an SCXML / sce:template root, applying `{$param}` bindings, and
    return {final id (lowercased) -> verdict} for every top-level `<final>`
    carrying a `<donedata><content>` JSON object."""
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
                out[fid.lower()] = (str(obj["verdict"]), str(obj.get("reason", "")))
    return out


def extract_donedata(scxml_path: Path) -> dict[str, Verdict]:
    """Donedata for a case, resolving an `<sce:use template=...>` reference.

    Template-based cases (ARP Group C/D, the SOMEIPSRV/IPv4/DHCPv4 field-check
    families, …) declare their finals once in a shared `.sce-template.xml`
    and bind the per-case `{$fail_state}` / `{$fail_reason}` via `<sce:use>`
    attributes — codegen substitutes them into the generated SM's stashed
    donedata. The audit mirrors that substitution so it sees the same
    donedata the runner will read at runtime."""
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


def audit_case(name: str) -> CaseReport:
    rep = CaseReport(name=name)
    header = (CASES_DIR / f"{name}.h").read_text(encoding="utf-8", errors="replace")
    trait = parse_verdict_for(header)
    if trait is None:
        rep.findings.append("UNPARSED: verdictFor body not parseable")
        trait = {}

    scxml_path = TESTS_DIR / name / f"{name}.scxml"
    if not scxml_path.is_file():
        rep.has_scxml = False
        rep.findings.append("NO_SCXML")
        return rep
    try:
        done = extract_donedata(scxml_path)
    except ET.ParseError as exc:
        rep.findings.append(f"UNPARSED: .scxml not parseable as XML ({exc})")
        return rep
    rep.has_donedata = bool(done)

    if not done:
        rep.findings.append(
            f"MISSING_DONEDATA: verdictFor has {len(trait)} final-state verdict(s),"
            f" .scxml has none"
        )
        return rep

    for state, dv in sorted(done.items()):
        tv = trait.get(state)
        if tv is None:
            rep.findings.append(
                f"FINAL_NO_VERDICT: final '{state}' donedata={dv} but verdictFor"
                f" has no matching State"
            )
        elif tv != dv:
            rep.findings.append(
                f"DRIFT: state '{state}' verdictFor={tv} != donedata={dv}"
            )
    for state, tv in sorted(trait.items()):
        if state not in done:
            rep.findings.append(
                f"VERDICT_NO_FINAL: verdictFor State '{state}'={tv} has no .scxml"
                f" final id"
            )
    return rep


def all_case_names() -> list[str]:
    """Registered cases only. A shared helper header (e.g.
    dhcpv4_router_option_egress_common.h, included by CM_05/_06) carries no
    `TC8_REGISTER_CASE` and is not a case, so it is excluded — the macro is
    the authoritative registration signal."""
    names = []
    for h in sorted(CASES_DIR.glob("*.h")):
        if h.name.startswith("_"):
            continue
        if "TC8_REGISTER_CASE" not in h.read_text(encoding="utf-8", errors="replace"):
            continue
        names.append(h.stem)
    return names


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cases", nargs="*", help="case names to audit (default: all)")
    ap.add_argument("--strict", action="store_true",
                    help="also fail the run on MISSING_DONEDATA")
    ap.add_argument("--summary", action="store_true",
                    help="print only per-finding-type counts")
    args = ap.parse_args()

    names = args.cases or all_case_names()
    reports = [audit_case(n) for n in names]

    counts: dict[str, int] = {}
    blocking = 0
    missing = 0
    for rep in reports:
        for f in rep.findings:
            kind = f.split(":")[0].split()[0]
            counts[kind] = counts.get(kind, 0) + 1
            if kind == "MISSING_DONEDATA":
                missing += 1
            elif kind in ("DRIFT", "UNPARSED", "FINAL_NO_VERDICT", "VERDICT_NO_FINAL", "NO_SCXML"):
                blocking += 1

    if not args.summary:
        for rep in reports:
            for f in rep.findings:
                print(f"{rep.name}: {f}")

    print("=" * 60)
    print(f"cases audited: {len(reports)}")
    for kind in sorted(counts):
        print(f"  {kind}: {counts[kind]}")
    clean = sum(1 for r in reports if not r.findings)
    print(f"  CLEAN (donedata present, no drift): {clean}")
    print("=" * 60)

    fail = blocking > 0 or (args.strict and missing > 0)
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
