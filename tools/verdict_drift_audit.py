#!/usr/bin/env python3
"""Enforce the conformance-verdict SSOT invariant.

Since the donedata-SSOT migration, each TC8 case declares its verdict exactly
once: in the SCXML `<final>`'s `<donedata><content>{"verdict":..,"reason":..}`
(or, for a template-based case, in the shared `.sce-template.xml` it binds via
`<sce:use>`). The generated SM stashes it and the runner reads it back
(`tc8::sce::verdictFromDonedata`,
src/sce_integration/include/sce_integration/verdict.h). There is no
second declaration — the legacy per-case `verdictFor(State)` switch was retired.

This tool guards that single source. For every registered case it checks:

  MISSING_DONEDATA  no `<final>` carries a donedata verdict (the runner would
                    fall back to the "running" sentinel = fail-closed)
  BAD_CLASS         a donedata verdict class is not one of the canonical
                    conformance classes (pass / fail / inconclusive / error)
  NO_SCXML          the case header exists but its .scxml does not
  UNPARSED          the .scxml is not well-formed XML
  QUIESCENCE_REACH  an `observed_quiescence` final is reached by anything but a
                    window timer (docs/verdict_policy.md §3)
  QUIESCENCE_UNGATED  an `observed_quiescence` final exists before every
                    hypothesis behind it is enforced (§8, Phases Q2-Q3)

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


def _composed_roots(scxml_path: Path) -> list[tuple[ET.Element, dict[str, str]]]:
    """The case root plus every template it binds via `<sce:use>`, each with its
    `{$param}` bindings — the parts codegen splices into one machine."""
    root = ET.parse(scxml_path).getroot()
    parts = [(root, {})]
    for el in root.iter():
        if _local(el.tag) == "use" and el.tag == f"{{{SCE_NS}}}use":
            tmpl_rel = el.get("template")
            if not tmpl_rel:
                continue
            tmpl_path = (scxml_path.parent / tmpl_rel).resolve()
            if not tmpl_path.is_file():
                continue
            bindings = {k: v for k, v in el.attrib.items() if k != "template"}
            parts.append((ET.parse(tmpl_path).getroot(), bindings))
    return parts


def extract_donedata(scxml_path: Path) -> dict[str, Verdict]:
    out: dict[str, Verdict] = {}
    for root, bindings in _composed_roots(scxml_path):
        out.update(_finals_from_root(root, bindings))
    return out


# --------------------------------------------------------------------------
# how each final is reached (docs/verdict_policy.md §3, `observed_quiescence`)
# --------------------------------------------------------------------------

# A `delay` that is all zeros in any unit ("0s", "0ms", "0") schedules an
# evaluation step, not an observation window.
_ZERO_DELAY_RE = re.compile(r"^\s*0+(\.0*)?\s*[a-z]*\s*$")

# How a transition is triggered: a window timer (the machine's own `<send>` with
# a non-zero delay), a zero-delay evaluation step, or anything else — an event
# the runner raises from a captured frame or an observation.
WINDOW, STEP, OTHER = "window", "step", "other"


def reach_kinds(parts: list[tuple[ET.Element, dict[str, str]]]) -> dict[str, set[str]]:
    """Map target id (lowercased) -> the trigger kinds of the transitions that
    reach it, over the composed machine. Events are global to a machine, so the
    timers of the case and of every bound template classify each other's
    transitions."""
    window: set[str] = set()
    step: set[str] = set()
    for root, b in parts:
        for el in root.iter():
            if _local(el.tag) != "send":
                continue
            event = _subst(el.get("event", ""), b)
            if el.get("delayexpr") is not None:
                window.add(event)  # an expression delay is a window unless proven zero
            elif el.get("delay") is not None:
                (step if _ZERO_DELAY_RE.match(el.get("delay", "")) else window).add(event)
    out: dict[str, set[str]] = {}
    for root, b in parts:
        for el in root.iter():
            if _local(el.tag) != "transition" or not el.get("target"):
                continue
            event = _subst(el.get("event", ""), b)
            kind = WINDOW if event in window else STEP if event in step else OTHER
            for target in _subst(el.get("target", ""), b).split():
                out.setdefault(target.lower(), set()).add(kind)
    return out


# False until every hypothesis behind an `observed_quiescence` fail is enforced:
# S, H1 and H2 by the CLI (Phase Q2, in the tree) and H3, the window bound, by the
# registry audit (Phase Q3). Until then the role could turn slowness into a fail,
# so authoring it is refused outright (docs/verdict_policy.md §8).
QUIESCENCE_GATED_AT_RUN_TIME = False


def quiescence_findings(done: dict[str, Verdict], reached: dict[str, set[str]],
                        gated: bool = QUIESCENCE_GATED_AT_RUN_TIME) -> list[str]:
    """An `observed_quiescence` final's evidence is an absence over a window, so
    every transition into it must be a window timer, and there must be one."""
    findings = []
    for state, (_cls, _reason, role) in sorted(done.items()):
        if role != "observed_quiescence":
            continue
        if not gated:
            findings.append(
                f"QUIESCENCE_UNGATED: final '{state}' is observed_quiescence, but its window bound "
                "(H3) is not yet audited (docs/verdict_policy.md §8, Phase Q3)"
            )
        kinds = reached.get(state, set())
        if not kinds:
            findings.append(f"QUIESCENCE_REACH: final '{state}' is observed_quiescence but nothing reaches it")
        elif kinds != {WINDOW}:
            bad = sorted(kinds - {WINDOW})
            findings.append(
                f"QUIESCENCE_REACH: final '{state}' is observed_quiescence but is reached by "
                f"{'/'.join(bad)} transition(s); its evidence is an absence, so only a window "
                "timer (a <send> with a non-zero delay) may decide it"
            )
    return findings


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
        parts = _composed_roots(scxml_path)
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
    rep.findings.extend(quiescence_findings(done, reach_kinds(parts)))
    return rep


def all_case_names() -> list[str]:
    """Registered cases only. A shared helper header (e.g.
    _dhcpv4_router_option_egress_common.h, included by CM_05/_06) carries no
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


_SELF_TEST_FINAL = (
    '<final id="{id}"><donedata><content>'
    '{{"verdict":"fail","reason":"r","role":"observed_quiescence"}}'
    "</content></donedata></final>"
)


def _self_test() -> int:
    """Each QUIESCENCE_REACH outcome on an inline machine, so a regression in the
    trigger classification shows here rather than as a silent CLEAN corpus."""
    ns = 'xmlns="http://www.w3.org/2005/07/scxml" xmlns:sce="http://sce.dev/ext"'

    def run(body: str, template: str | None = None, bindings: dict[str, str] | None = None,
            gated: bool = True) -> list[str]:
        parts = [(ET.fromstring(f"<scxml {ns}>{body}</scxml>"), {})]
        if template is not None:
            parts.append((ET.fromstring(f"<sce:template {ns}>{template}</sce:template>"), bindings or {}))
        done: dict[str, Verdict] = {}
        for root, b in parts:
            done.update(_finals_from_root(root, b))
        return quiescence_findings(done, reach_kinds(parts), gated=gated)

    q = _SELF_TEST_FINAL.format(id="fail_q")
    window = '<state id="s"><onentry><send event="t" delay="5s"/></onentry><transition event="t" target="fail_q"/></state>'
    cases = [
        ("window timer only", run(window + q), 0),
        ("frame-reached", run('<state id="s"><transition event="arp_observed" target="fail_q"/></state>' + q), 1),
        ("zero-delay step", run('<state id="s"><onentry><send event="e" delay="0ms"/></onentry>'
                                '<transition event="e" target="fail_q"/></state>' + q), 1),
        ("window and frame", run(window.replace("</state>", '<transition event="f" target="fail_q"/></state>') + q), 1),
        ("unreached", run('<state id="s"/>' + q), 1),
        ("timer bound through a template param",
         run('<state id="s"><transition event="dl" target="fail_q"/></state>' + q,
             '<state id="x"><onentry><send event="{$ev}" delay="2s"/></onentry></state>', {"ev": "dl"}), 0),
    ]
    cases.append(("well-formed but not yet gated at run time", run(window + q, gated=False), 1))
    bad = 0
    for label, findings, want in cases:
        ok = len(findings) == want
        bad += 0 if ok else 1
        print(f"{'ok  ' if ok else 'FAIL'} {label}: {len(findings)} finding(s), want {want}")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("cases", nargs="*", help="case names to audit (default: all)")
    ap.add_argument("--summary", action="store_true", help="print only per-finding-type counts")
    ap.add_argument("--self-test", action="store_true", help="run the trigger-classification self-test")
    args = ap.parse_args()
    if args.self_test:
        return _self_test()

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
