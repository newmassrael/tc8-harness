#!/usr/bin/env python3
"""Enforce negative-coverage EXHAUSTIVENESS + soundness (docs/verdict_policy.md
Section 6, debt D7).

Every registered positive conformance case must carry a non-vacuity DISPOSITION
that proves its verdict guard is checkable — that a non-conformant DUT would land
on `fail`. ISO 9646 suite validation / mutation analysis: a test whose guard can
never fire is vacuous and validates nothing. The four terminal dispositions are:

  SOUND_ROW        a NEG_ROW lands the conformant DUT on a `fail` final via a
                   deliberately-wrong --expect token (expect-flip negative;
                   dut/env/smoke-test.sh run_negative_case).
  FAULT_INJECTION  a `<case>_neg` registered case drives a faulty DUT flavour to
                   `fail` (empirically verified — the Phase F north star, realised).
  REGISTRY         conformant_absence_registry.json — the guard asserts DUT
                   BEHAVIOUR (must emit a correct frame / must not emit a
                   prohibited one), which no --expect can fault; non-vacuity is
                   structural, awaiting a fault-injection negative.
  DEFERRED         deferred_negatives.json — an expect-flippable guard with no
                   sound negative yet, each carrying an explicit reason (Linux
                   deviation, needs-parameterise) until fixed.

A positive case in none of these is UNDISPOSED: its guard's non-vacuity is unproven
and untracked. The exhaustiveness ledger (negative_coverage_undisposed.txt)
grandfathers today's UNDISPOSED set so the backlog is retired incrementally; --check
rejects any NEW undisposed case and forces the ledger to shrink as cases are
disposed. When the ledger empties, every positive case is *covered* — accounted for
by a disposition.

Coverage is not correctness. This audit proves every case has a disposition; it does
NOT prove each disposition is genuine. The correctness of a disposition is a separate
(largely empirical, Phase F) concern: a REGISTRY entry's class/property is a review
property; a FAULT_INJECTION pairing is validated by the `_neg` case's own green run;
and a SOUND_ROW must be a real value-flip, not observation suppression. The one
correctness hole this audit *does* close mechanically is the last: a "sound" row that
flips an L3 source-IP filter (ipv4/icmpv4 `dut_iface_ip`) sends every guard out of
reach and lands on an absence/timeout `fail` — it proves the case timed out, not that
the guard reacts to a wrong value. Such SPURIOUS rows are rejected, not counted as a
SOUND_ROW disposition.

`_neg` cases are negative mechanisms, not positive cases; they are excluded from the
universe. Each must pair with a real base case and carry a `fail` final (a negative
that cannot fail catches nothing).

Also enforced: registry structural validity (every `fail` final covered by a guard;
declared classes; non-empty property; a registry case carries no row and no _neg
sibling) and NEG_ROW integrity (no STALE row whose reason is not a final).

Default (no args): print the census. --check: enforce the invariants (gates
build-test.yml + pre-commit). --write-ledger: regenerate the exhaustiveness ledger
from the current UNDISPOSED set (bootstrap / after a batch of dispositions).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verdict_drift_audit import (  # noqa: E402
    REPO,
    SCE_NS,
    TESTS_DIR,
    _local,
    _subst,
    all_case_names,
    extract_donedata,
)

SMOKE_SH = REPO / "dut" / "env" / "smoke-test.sh"
HERE = Path(__file__).resolve().parent
LEDGER = HERE / "negative_coverage_undisposed.txt"
REGISTRY = HERE / "conformant_absence_registry.json"
DEFERRED = HERE / "deferred_negatives.json"
FAULT_COVERAGE = HERE / "fault_injection_coverage.json"

# A `_neg` case-name suffix: `_neg` for a single-guard case, or `_neg<n>`
# (`_neg2`, `_neg3`, ...) for one of several fault-injection variants of a
# multi-guard case (one per fail-final). Used to split positives from negatives
# and to derive the positive base a `_neg<n>` validates.
_NEG_RE = re.compile(r"_neg\d*$")

# One `NEG_ROWS` entry: "CASE_ID|wrong_token|<class>:<reason>".
_ROW_RE = re.compile(r'"([^"|]+)\|([^"|]*)\|([a-z_]+):([^"]+)"')

# Token keys that are the L3 source-IP observation filter every guard conjuncts on.
# Flipping one suppresses observation entirely, so the case lands on an
# absence/timeout `fail` -- a SPURIOUS "sound" row that validates nothing. (The
# expected-VALUE keys `dut_iface_ip`/`arp.dut_iface_ip` are a different namespace
# and are genuine value flips.)
SPURIOUS_FILTER_KEYS = {"ipv4.dut_iface_ip", "icmpv4.dut_iface_ip"}

# Phase F (docs/verdict_policy.md Section 6.1): the empirical-verification ratchet.
# Coverage (undisposed -> 0) is reached; the live metric is now empirical proof.
# FAULT_INJECTION proofs only ever grow -- --check floors the count so a _neg case
# can never silently regress. The REGISTRY set is the work-list (--phase-f). Bump
# the floor when new _neg cases land.
FAULT_INJECTION_FLOOR = 19

# A REGISTRY guard is empirically faultable only where the misbehaviour can be
# produced. Firmware families (tc8-dut / vsomeip app) take a _neg flavor case (the
# realised ipv4_autoconf pattern); kernel-stack families run against the Linux
# reference, which cannot be made to misbehave -- faultable only on the lwIP DUT,
# else structural with the reference stack as oracle. Longest-prefix wins
# (IPV4_AUTOCONF before IPV4).
FIRMWARE_FAMILIES = ("IPV4_AUTOCONF", "DHCPV4", "SOMEIP_ETS", "SOMEIPSRV", "ARP")
KERNEL_FAMILIES = ("ICMPV4", "TCP", "UDP", "IPV4")


def case_family(case_id: str) -> str:
    c = case_id.upper()
    for fam in (*FIRMWARE_FAMILIES, *KERNEL_FAMILIES):
        if c.startswith(fam):
            return fam
    return c.split("_")[0]


@dataclass(frozen=True)
class NegRow:
    case_id: str
    token: str
    exp_class: str
    exp_reason: str


def parse_neg_rows(smoke_path: Path) -> list[NegRow]:
    """Extract the `NEG_ROWS=( ... )` array (the negative-set SSOT). Commented-out
    lines (leading `#`) are skipped so example rows don't count."""
    text = smoke_path.read_text(encoding="utf-8")
    m = re.search(r"\n\s*NEG_ROWS=\(\n(.*?)\n\s*\)\n", text, re.S)
    if not m:
        raise SystemExit("negative_coverage_audit: NEG_ROWS=( ... ) block not found")
    rows: list[NegRow] = []
    for raw in m.group(1).splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        rm = _ROW_RE.search(line)
        if not rm:
            continue
        rows.append(NegRow(rm.group(1), rm.group(2), rm.group(3), rm.group(4)))
    return rows


def reason_classes(case: str) -> dict[str, set[str]] | None:
    """reason -> {verdict classes that final carries}. None if no .scxml. `case` is
    the lower-case directory/case name."""
    scxml = TESTS_DIR / case / f"{case}.scxml"
    if not scxml.is_file():
        return None
    out: dict[str, set[str]] = {}
    for cls, reason, _role in extract_donedata(scxml).values():
        if reason:
            out.setdefault(reason, set()).add(cls)
    return out


def fail_reasons_of(case: str) -> set[str]:
    """The set of `fail`-final reasons a positive case's .scxml carries -- the
    guards that a FAULT_INJECTION promotion must each prove reachable. `case` is the
    lower-case directory/case name. Empty if no .scxml or no fail finals."""
    rc = reason_classes(case)
    if rc is None:
        return set()
    return {reason for reason, classes in rc.items() if "fail" in classes}


def final_classes(case: str) -> set[str]:
    """The set of verdict classes the case's .scxml finals carry (pass / fail /
    inconclusive / error). Unlike reason_classes this counts reason-less finals
    (a `pass` donedata carries no reason). `case` is the lower-case case name."""
    scxml = TESTS_DIR / case / f"{case}.scxml"
    if not scxml.is_file():
        return set()
    return {cls for cls, _reason, _role in extract_donedata(scxml).values()}


def row_kind(row: NegRow) -> str:
    """Classify a NEG_ROW against its case's finals: SOUND (reason -> fail),
    VACUOUS (reason -> inconclusive), STALE (reason is not a final), UNKNOWN."""
    rc = reason_classes(row.case_id.lower())
    if rc is None:
        return "UNKNOWN"
    classes = rc.get(row.exp_reason)
    if classes is None:
        return "STALE"
    if "fail" in classes:
        return "SOUND"
    if "inconclusive" in classes:
        return "VACUOUS"
    return "OTHER"


def load_registry() -> tuple[dict[str, dict], dict[str, str]]:
    if not REGISTRY.is_file():
        return {}, {}
    data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    return data.get("cases", {}), data.get("classes", {})


def load_deferred() -> dict[str, str]:
    """deferred_negatives.json: case_id -> reason. An expect-flippable guard with no
    sound negative yet (Linux deviation, needs-parameterise). Empty if absent."""
    if not DEFERRED.is_file():
        return {}
    data = json.loads(DEFERRED.read_text(encoding="utf-8"))
    return data.get("cases", {})


def load_fault_coverage() -> dict[str, dict[str, str]]:
    """fault_injection_coverage.json: base_case_id -> {fail_reason: neg_case_id}.
    The per-fail-final SSOT for a MULTI-GUARD case whose guards cannot all be proven
    by one `_neg` (one run reaches one final). A single-guard case needs no entry --
    its lone `_neg` covers its lone fail-final. Empty if absent."""
    if not FAULT_COVERAGE.is_file():
        return {}
    data = json.loads(FAULT_COVERAGE.read_text(encoding="utf-8"))
    return data.get("cases", {})


def validate_registry(cases: dict[str, dict], classes: dict[str, str]) -> list[str]:
    """Structural validation of each registry entry (docs/verdict_policy.md Section
    6). Each case carries a `guards` list — one guard per `fail` final (the exact
    unit a DUT-mutation mutant must trip), or a single `liveness` guard for a case
    with no `fail` final. Per guard: the class is declared; a non-`liveness` guard
    names a real `fail` final; a `liveness` guard names none and the case has no
    `fail` final; the `property` is non-empty. Completeness: every `fail` final is
    covered by a guard."""
    findings: list[str] = []
    for case_id, entry in cases.items():
        guards = entry.get("guards")
        if not isinstance(guards, list) or not guards:
            findings.append(f"REGISTRY_INVALID: {case_id} has no guards list")
            continue
        rc = reason_classes(case_id.lower())
        if rc is None:
            findings.append(f"REGISTRY_INVALID: {case_id} has no registered .scxml")
            continue
        case_fail_reasons = {r for r, v in rc.items() if "fail" in v}
        covered: set[str] = set()
        for g in guards:
            cls = g.get("class")
            if cls not in classes:
                findings.append(f"REGISTRY_INVALID: {case_id} guard class '{cls}' is not a declared class")
                continue
            if not g.get("property"):
                findings.append(f"REGISTRY_INVALID: {case_id} guard ({cls}) has an empty property")
            if cls == "liveness":
                if g.get("fail_reason"):
                    findings.append(f"REGISTRY_INVALID: {case_id} liveness guard names a fail_reason")
                elif case_fail_reasons:
                    findings.append(f"REGISTRY_INVALID: {case_id} is liveness but the case has fail finals")
                continue
            reason = g.get("fail_reason")
            if not reason:
                findings.append(f"REGISTRY_INVALID: {case_id} ({cls}) guard must name a structural fail_reason")
            elif "fail" not in rc.get(reason, set()):
                findings.append(f"REGISTRY_INVALID: {case_id} fail_reason '{reason}' is not a fail final")
            else:
                covered.add(reason)
        missing = case_fail_reasons - covered
        if missing:
            findings.append(f"REGISTRY_INCOMPLETE: {case_id} fail finals not covered by a guard: {sorted(missing)}")
    return findings


# Events that fire on the listen-window expiring with no observation (silence).
# Deliberately NOT "complete" alone -- that also matches phase-progression
# signals like `conflicts_complete` (the injected conflicts are done), which is
# not a silence outcome; the genuine silence-window completions carry "silence".
_DEADLINE_EVENTS = ("deadline", "timeout", "window", "silence")

# Registry cases whose authored `class` legitimately disagrees with the
# deadline-target heuristic below: a `prohibited_emission` fail (silence of the
# forbidden frame is conformant) sits in a case that nonetheless requires a
# POSITIVE observation to PASS, so its deadline transition reaches `inconclusive`
# rather than `pass`. The heuristic would read that as incorrect_emission; the
# authored class is correct. Each entry records why (reviewed, docs/verdict_
# policy.md Section 6).
CLASS_STRUCTURE_EXCEPTIONS = {
    "ARP_22": "prohibited: forbidden UDP to the dropped frame's MAC; PASS requires observing the DUT's own ARP Request, so the deadline reaches inconclusive",
    "ARP_28": "prohibited: forbidden UDP to the dropped frame's MAC; PASS requires observing the DUT's own ARP Request, so the deadline reaches inconclusive",
    "ARP_38": "prohibited: forbidden UDP to the dropped frame's MAC; PASS requires observing the DUT's own ARP Request, so the deadline reaches inconclusive",
    "SOMEIP_ETS_096": "prohibited: forbidden SubscribeAck; PASS requires observing a NACK, so silence reaches inconclusive (not pass)",
}


def _derive_guard_classes(case_lower: str) -> dict[str, set[str]]:
    """Per `fail` final reason, the class implied by the .scxml silence-semantics.
    A fail whose source state reaches `pass` on a deadline (silence is a
    conformant outcome) implies `prohibited_emission`; a deadline reaching
    `inconclusive` (the DUT must emit, absence is non-conclusive) implies
    `incorrect_emission`. Reasons whose source state carries no deadline
    transition (e.g. a stall-watchdog) are omitted — the structure does not
    determine the class, so nothing is asserted. Template `<sce:use>` bindings
    are applied so template-backed cases resolve."""
    scxml = TESTS_DIR / case_lower / f"{case_lower}.scxml"
    if not scxml.is_file():
        return {}
    root = ET.parse(scxml).getroot()
    done = extract_donedata(scxml)
    roots = [(root, {})]
    for el in root.iter():
        if _local(el.tag) == "use" and el.tag == f"{{{SCE_NS}}}use":
            tmpl = el.get("template")
            tp = (scxml.parent / tmpl).resolve() if tmpl else None
            if tp and tp.is_file():
                bindings = {k: v for k, v in el.attrib.items() if k != "template"}
                roots.append((ET.parse(tp).getroot(), bindings))
    states: dict[str, list[tuple[str, str]]] = {}
    for r, b in roots:
        for st in r.iter():
            if _local(st.tag) != "state":
                continue
            sid = _subst(st.get("id", ""), b)
            rows = [
                (tr.get("event", "") or "", _subst(tr.get("target", ""), b).lower())
                for tr in st
                if _local(tr.tag) == "transition"
            ]
            if rows:
                states.setdefault(sid, []).extend(rows)
    fail_reason = {fid: rsn for fid, (cls, rsn, _r) in done.items() if cls == "fail"}
    out: dict[str, set[str]] = {}
    for fid, reason in fail_reason.items():
        cls = None
        for sid, rows in states.items():
            if not any(tgt == fid for _ev, tgt in rows):
                continue
            # Deadline/silence transitions in the fail's source state. The target
            # is `pass` (silence is the conformant verdict) or an onward progress
            # state (silence completes a window and the conformant flow continues,
            # e.g. a rate-limit silence -> re-pick) -> silence is conformant ->
            # prohibited_emission. A deadline reaching `inconclusive` (the DUT must
            # emit; absence is non-conclusive) -> incorrect_emission.
            dl = [
                (done.get(tgt, ("?", "", ""))[0], tgt)
                for ev, tgt in rows
                if any(k in ev for k in _DEADLINE_EVENTS)
            ]
            if any(c == "pass" or (c == "?" and t) for c, t in dl):
                cls = "prohibited_emission"
                break
            if any(c == "inconclusive" for c, _t in dl):
                cls = "incorrect_emission"
        if cls and reason:
            out.setdefault(reason, set()).add(cls)
    return out


def check_class_structure(cases: dict[str, dict]) -> list[str]:
    """Cross-validate each authored guard `class` against the .scxml silence-
    semantics (docs/verdict_policy.md Section 6). The class is authored because
    it encodes whether silence is conformant, which is not always mechanically
    derivable; where the deadline target DOES determine it, the authored class
    must agree (or the case must be allow-listed in CLASS_STRUCTURE_EXCEPTIONS
    with a reason). Catches a mislabelled prohibited/incorrect guard, which the
    structural audit alone would pass."""
    findings: list[str] = []
    for case_id, entry in cases.items():
        if case_id in CLASS_STRUCTURE_EXCEPTIONS:
            continue
        derived = _derive_guard_classes(case_id.lower())
        for g in entry.get("guards", []):
            cls = g.get("class")
            reason = g.get("fail_reason")
            if cls == "liveness" or not reason:
                continue
            want = derived.get(reason)
            if want and cls not in want:
                findings.append(
                    f"CLASS_STRUCTURE: {case_id} guard '{reason}' authored {cls} "
                    f"but .scxml silence-semantics imply {sorted(want)} "
                    f"(fix the class or allow-list with a reason)"
                )
    return findings


def load_ledger() -> set[str]:
    if not LEDGER.is_file():
        return set()
    out = set()
    for line in LEDGER.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.add(line)
    return out


def ledger_text(cases: set[str]) -> str:
    header = (
        "# negative-coverage exhaustiveness ledger (debt D7 -- docs/verdict_policy.md\n"
        "# Section 6). Each line is a positive case_id whose verdict guard has NO\n"
        "# non-vacuity disposition yet (not SOUND_ROW / FAULT_INJECTION / REGISTRY /\n"
        "# DEFERRED). Generated by tools/negative_coverage_audit.py --write-ledger.\n"
        "# Disposing a case (add a sound NEG_ROW, register it, add a _neg case, or\n"
        "# track it in deferred_negatives.json) MUST delete its line here too;\n"
        "# --check fails on a new undisposed case or a stale (now-disposed) entry.\n"
        "# When this file is empty every positive case is disposed -- the SSOT is\n"
        "# proven complete.\n"
    )
    return header + "".join(f"{c}\n" for c in sorted(cases))


@dataclass
class Model:
    rows: list[NegRow]
    positives: list[str]              # lower-case case names (non-_neg)
    neg_names: list[str]              # lower-case _neg / _neg<n> case names
    fault_bases: set[str]             # lower-case bases that have a _neg sibling
    registry: dict[str, dict]
    reg_classes: dict[str, str]
    deferred: dict[str, str]
    fault_coverage: dict[str, dict[str, str]]  # base -> {fail_reason: neg_case_id}
    sound_cases: set[str]             # lower-case cases with a genuine SOUND row
    vacuous_cases: set[str]           # lower-case cases whose only row(s) are VACUOUS
    spurious_rows: list[NegRow]       # SOUND-shaped rows that flip an L3 src-IP filter
    disposition: dict[str, str]       # case -> SOUND_ROW/FAULT_INJECTION/REGISTRY/DEFERRED/UNDISPOSED


def build_model() -> Model:
    rows = parse_neg_rows(SMOKE_SH)
    names = all_case_names()
    neg_names = [n for n in names if _NEG_RE.search(n)]
    positives = [n for n in names if not _NEG_RE.search(n)]
    fault_bases = {_NEG_RE.sub("", n) for n in neg_names}
    registry, reg_classes = load_registry()
    deferred = load_deferred()
    fault_coverage = load_fault_coverage()
    reg_lower = {k.lower() for k in registry}
    def_lower = {k.lower() for k in deferred}

    sound_cases: set[str] = set()
    spurious_rows: list[NegRow] = []
    case_has_row: set[str] = set()
    for r in rows:
        cid = r.case_id.lower()
        case_has_row.add(cid)
        if row_kind(r) == "SOUND":
            if r.token.split("=", 1)[0] in SPURIOUS_FILTER_KEYS:
                spurious_rows.append(r)   # observation suppression, not a value flip
            else:
                sound_cases.add(cid)
    vacuous_cases = {c for c in case_has_row if c not in sound_cases}

    disposition: dict[str, str] = {}
    for c in positives:
        if c in sound_cases:
            disposition[c] = "SOUND_ROW"
        elif c in fault_bases:
            disposition[c] = "FAULT_INJECTION"
        elif c in reg_lower:
            disposition[c] = "REGISTRY"
        elif c in def_lower:
            disposition[c] = "DEFERRED"
        else:
            disposition[c] = "UNDISPOSED"
    return Model(rows, positives, neg_names, fault_bases, registry, reg_classes,
                 deferred, fault_coverage, sound_cases, vacuous_cases, spurious_rows,
                 disposition)


def validate_fault_coverage(m: Model) -> list[str]:
    """Per-fail-final coverage for FAULT_INJECTION cases (docs/verdict_policy.md
    Section 6.1). A `_neg` run reaches ONE final, so a multi-guard case (>1 `fail`
    final) cannot be honestly promoted by a single `_neg` -- partial promotion would
    silently drop the unproven guards from the registry. Enforce that:

      * every multi-fail-final FAULT_INJECTION case has a fault_injection_coverage
        entry whose keys EXACTLY cover its .scxml fail-finals (no uncovered guard,
        no stale reason), and
      * every declared neg_case_id is a real `_neg<n>` sibling of that base.

    A single-fail-final case needs no entry: its lone `_neg` covers its lone guard.
    """
    findings: list[str] = []
    pos = set(m.positives)
    neg_set = set(m.neg_names)

    # 1. Structural validity of each declared coverage entry.
    for base, mapping in m.fault_coverage.items():
        base_l = base.lower()
        if base_l not in pos:
            findings.append(f"FAULT_COVERAGE_INVALID: {base} is not a registered positive case")
            continue
        declared = set(mapping.keys())
        actual = fail_reasons_of(base_l)
        if declared != actual:
            findings.append(
                f"FAULT_COVERAGE_INCOMPLETE: {base} coverage keys {sorted(declared)} "
                f"!= .scxml fail-finals {sorted(actual)} (cover every guard, drop stale)"
            )
        for reason, neg in mapping.items():
            neg_l = neg.lower()
            if neg_l not in neg_set:
                findings.append(
                    f"FAULT_COVERAGE_INVALID: {base} reason '{reason}' -> '{neg}' is not a registered _neg case"
                )
                continue
            if _NEG_RE.sub("", neg_l) != base_l:
                findings.append(
                    f"FAULT_COVERAGE_INVALID: {neg} (reason '{reason}') is not a _neg variant of base {base}"
                )
                continue
            # The mapped _neg must have a reachable `pass` (the violation-detected
            # path) AND exactly one `fail` final (the conformant-DUT branch -- the
            # live fail_compliant_* outcome, docs/verdict_policy.md Section 6.1). A
            # second `fail` final is an unreachable mis-roled catch-net (a
            # flavor-wiring fault is `inconclusive`/`error`, not a DUT violation);
            # zero means the negative cannot succeed. The semantic link (this _neg
            # proves THIS guard) is grounded by the flavor + the CI smoke green run,
            # not statically here -- that is the honest boundary of this gate.
            classes = final_classes(neg_l)
            if "pass" not in classes:
                findings.append(
                    f"FAULT_COVERAGE_INVALID: {neg} has no `pass` final (the violation-detected path)"
                )
            n_fail = len(fail_reasons_of(neg_l))
            if n_fail != 1:
                findings.append(
                    f"FAULT_COVERAGE_INVALID: {neg} has {n_fail} fail finals; a _neg "
                    f"carries exactly one (the conformant-DUT branch) -- route "
                    f"wrong-stage catches to inconclusive"
                )

    # 2. A multi-fail-final FAULT_INJECTION case MUST declare its coverage. Without
    #    an entry a single `_neg` would silently promote the case while proving only
    #    one of its guards.
    cov_lower = {b.lower() for b in m.fault_coverage}
    for case, disp in m.disposition.items():
        if disp != "FAULT_INJECTION":
            continue
        reasons = fail_reasons_of(case)
        if len(reasons) > 1 and case not in cov_lower:
            findings.append(
                f"PARTIAL_FAULT_INJECTION: {case} has {len(reasons)} fail-finals "
                f"{sorted(reasons)} but no fault_injection_coverage.json entry; one "
                f"_neg proves one final"
            )
    return findings


def cross_findings(m: Model) -> list[str]:
    """Invariants that must always hold (independent of the ratchet)."""
    findings: list[str] = []
    reg_lower = {k.lower() for k in m.registry}
    def_lower = {k.lower() for k in m.deferred}
    pos = set(m.positives)

    # STALE rows: a row whose reason is not a final in the case.
    for r in m.rows:
        if row_kind(r) == "STALE":
            findings.append(f"STALE: {r.case_id} NEG_ROW reason '{r.exp_reason}' is not a final in the case")
        if row_kind(r) == "UNKNOWN":
            findings.append(f"UNKNOWN: {r.case_id} has no registered .scxml")

    # A registry case must carry no NEG_ROW and no _neg sibling, and be a positive.
    row_cases = {r.case_id.lower() for r in m.rows}
    for c in reg_lower:
        if c in row_cases:
            findings.append(f"REGISTERED_WITH_ROW: {c} is conformant-absence (registry); remove its NEG_ROW")
        if c in m.fault_bases:
            findings.append(f"REGISTRY_AND_FAULT: {c} has a _neg case (FAULT_INJECTION); drop the registry entry")
        if c not in pos:
            findings.append(f"REGISTRY_NOT_POSITIVE: {c} is not a registered positive case")

    # A deferred case must not also be disposed elsewhere, and must be a positive.
    for c in def_lower:
        if c not in pos:
            findings.append(f"DEFERRED_NOT_POSITIVE: {c} is not a registered positive case")
        elif m.disposition.get(c) != "DEFERRED":
            findings.append(f"DEFERRED_REDUNDANT: {c} is already {m.disposition.get(c)}; drop the deferred entry")

    # A SPURIOUS row flips the L3 src-IP filter and lands on absence/timeout: it
    # proves nothing and must not masquerade as a SOUND_ROW disposition.
    for r in m.spurious_rows:
        findings.append(
            f"SPURIOUS_SOUND: {r.case_id} flips L3 filter '{r.token}' -> absence "
            f"fail '{r.exp_reason}'; remove it (the guard is not value-faulted)"
        )

    # Every _neg / _neg<n> mechanism must pair with a registered positive base and be
    # able to fail (a negative with no `fail` final catches nothing).
    for neg in m.neg_names:
        base = _NEG_RE.sub("", neg)
        if base not in pos:
            findings.append(f"ORPHAN_NEG: {neg} has no registered positive base case")
        neg_rc = reason_classes(neg)
        if neg_rc is not None and not any("fail" in v for v in neg_rc.values()):
            findings.append(f"NEG_NO_FAIL: {neg} has no fail final; it cannot catch a fault")

    findings.extend(validate_registry(m.registry, m.reg_classes))
    findings.extend(check_class_structure(m.registry))
    findings.extend(validate_fault_coverage(m))

    # Phase F empirical-verification ratchet: FAULT_INJECTION proofs only grow.
    fault_inj = sum(1 for d in m.disposition.values() if d == "FAULT_INJECTION")
    if fault_inj < FAULT_INJECTION_FLOOR:
        findings.append(
            f"PHASE_F_REGRESSION: FAULT_INJECTION {fault_inj} < floor "
            f"{FAULT_INJECTION_FLOOR}; a _neg case was lost (or bump the floor)"
        )
    return findings


def is_liveness_only(entry: dict) -> bool:
    """A registry case whose every guard is `liveness` has no reachable `fail` final
    (docs/verdict_policy.md Section 6: absence is `inconclusive`, Section 2 clause 4),
    so it is structurally NOT empirically faultable and can never be promoted to
    FAULT_INJECTION. It stays terminal in REGISTRY by policy — excluded from the
    Phase F faultable target, exactly as the kernel-stack guards are. The registry
    `class` is the SSOT for faultability."""
    guards = entry.get("guards", [])
    return bool(guards) and all(g.get("class") == "liveness" for g in guards)


def phase_f_report(m: Model) -> int:
    """Phase F work-list (docs/verdict_policy.md Section 6.1): which REGISTRY guards
    are empirically faultable on the firmware DUT (the FAULT_INJECTION target) vs
    structurally terminal (liveness, no reachable `fail`) vs run against the Linux
    reference stack (kernel oracle / lwIP-DUT track only)."""
    from collections import Counter
    fw_fams = set(FIRMWARE_FAMILIES)
    fault = [c for c, d in m.disposition.items() if d == "FAULT_INJECTION"]
    # Registry split on two axes: family (who implements it) x faultability (does the
    # guard have a reachable `fail` — i.e. is it NOT liveness-only). liveness-only
    # guards are excluded from the target on BOTH families (no `fail` to drive).
    fw_fault, fw_live, kn_fault, kn_live = [], [], [], []
    for case_id, entry in m.registry.items():
        c = case_id.lower()
        live = is_liveness_only(entry)
        bucket = (fw_live if live else fw_fault) if case_family(c) in fw_fams \
            else (kn_live if live else kn_fault)
        bucket.append(c)

    def by_family(cases):
        return sorted(Counter(case_family(c) for c in cases).items(), key=lambda x: -x[1])

    target = len(fault) + len(fw_fault)
    pct = 100.0 * len(fault) / target if target else 100.0
    print("Phase F -- empirical verification (docs/verdict_policy.md Section 6.1)")
    print("=" * 68)
    print(f"  verified (FAULT_INJECTION, floor {FAULT_INJECTION_FLOOR}): {len(fault)}")
    print(f"  firmware faultable target: {len(fault)}/{target} proven ({pct:.0f}%)")
    print("  -- firmware faultable REGISTRY backlog (the work-list) --")
    for fam, n in by_family(fw_fault):
        print(f"     {fam:14} {n}")
    print(f"  -- firmware liveness REGISTRY (no reachable fail; terminal by policy, NOT a target): {len(fw_live)} --")
    for fam, n in by_family(fw_live):
        print(f"     {fam:14} {n}")
    print(f"  -- kernel-stack REGISTRY (Linux=oracle; lwIP-DUT track only): {len(kn_fault)} faultable + {len(kn_live)} liveness --")
    for fam, n in by_family(kn_fault + kn_live):
        print(f"     {fam:14} {n}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--check", action="store_true", help="enforce the invariants (gate CI/pre-commit)")
    ap.add_argument("--write-ledger", action="store_true", help="regenerate the exhaustiveness ledger from the current UNDISPOSED set")
    ap.add_argument("--phase-f", action="store_true", help="print the empirical-verification (fault-injection) work-list")
    args = ap.parse_args()

    m = build_model()
    undisposed = {c for c, d in m.disposition.items() if d == "UNDISPOSED"}

    if args.phase_f:
        return phase_f_report(m)

    if args.write_ledger:
        LEDGER.write_text(ledger_text(undisposed), encoding="utf-8")
        print(f"wrote {LEDGER.relative_to(REPO)} ({len(undisposed)} undisposed)")
        return 0

    ledger = load_ledger()
    counts: dict[str, int] = {}
    for d in m.disposition.values():
        counts[d] = counts.get(d, 0) + 1

    if not args.check:
        print(f"negative-coverage exhaustiveness ({len(m.positives)} positive cases)")
        print("=" * 64)
        for kind in ("SOUND_ROW", "FAULT_INJECTION", "REGISTRY", "DEFERRED", "UNDISPOSED"):
            print(f"  {kind:16} = {counts.get(kind, 0)}")
        print("=" * 64)
        print(f"  NEG_ROWS: {len(m.rows)} ({len(m.sound_cases)} sound cases, "
              f"{len(m.vacuous_cases)} cases with only vacuous rows)")
        print(f"  registry: {len(m.registry)} | deferred: {len(m.deferred)} | "
              f"_neg mechanisms: {len(m.neg_names)} over {len(m.fault_bases)} bases")
        print(f"  exhaustiveness ledger: {len(ledger)} entries  ({LEDGER.relative_to(REPO)})")
        for f in cross_findings(m):
            print(f"  {f}")
        new_debt = undisposed - ledger
        gone = ledger - undisposed
        if new_debt:
            print(f"  NEW undisposed (not in ledger): {len(new_debt)} -> {sorted(new_debt)[:20]}")
        if gone:
            print(f"  ledger entries now disposed (remove them): {len(gone)} -> {sorted(gone)[:20]}")
        return 0

    findings = cross_findings(m)
    for c in sorted(undisposed - ledger):
        findings.append(f"NEW_UNDISPOSED: {c} has no non-vacuity disposition; add a sound row, register, _neg, or defer")
    for c in sorted(ledger - undisposed):
        findings.append(f"STALE_LEDGER: {c} is now disposed; remove it from {LEDGER.name}")

    print(
        f"exhaustiveness: {counts.get('SOUND_ROW',0)} sound / {counts.get('FAULT_INJECTION',0)} fault-inj / "
        f"{counts.get('REGISTRY',0)} registry / {counts.get('DEFERRED',0)} deferred / "
        f"{len(undisposed)} undisposed (ledger {len(ledger)}) / {len(m.positives)} positive"
    )
    for f in findings:
        print(f"  {f}")
    if findings:
        print(f"FAIL: {len(findings)} finding(s)")
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
