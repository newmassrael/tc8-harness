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
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verdict_drift_audit import (  # noqa: E402
    REPO,
    TESTS_DIR,
    all_case_names,
    extract_donedata,
)

SMOKE_SH = REPO / "dut" / "env" / "smoke-test.sh"
HERE = Path(__file__).resolve().parent
LEDGER = HERE / "negative_coverage_undisposed.txt"
REGISTRY = HERE / "conformant_absence_registry.json"
DEFERRED = HERE / "deferred_negatives.json"

# One `NEG_ROWS` entry: "CASE_ID|wrong_token|<class>:<reason>".
_ROW_RE = re.compile(r'"([^"|]+)\|([^"|]*)\|([a-z_]+):([^"]+)"')

# Token keys that are the L3 source-IP observation filter every guard conjuncts on.
# Flipping one suppresses observation entirely, so the case lands on an
# absence/timeout `fail` -- a SPURIOUS "sound" row that validates nothing. (The
# expected-VALUE keys `dut_iface_ip`/`arp.dut_iface_ip` are a different namespace
# and are genuine value flips.)
SPURIOUS_FILTER_KEYS = {"ipv4.dut_iface_ip", "icmpv4.dut_iface_ip"}


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
    fault_bases: set[str]             # lower-case bases that have a _neg sibling
    registry: dict[str, dict]
    reg_classes: dict[str, str]
    deferred: dict[str, str]
    sound_cases: set[str]             # lower-case cases with a genuine SOUND row
    vacuous_cases: set[str]           # lower-case cases whose only row(s) are VACUOUS
    spurious_rows: list[NegRow]       # SOUND-shaped rows that flip an L3 src-IP filter
    disposition: dict[str, str]       # case -> SOUND_ROW/FAULT_INJECTION/REGISTRY/DEFERRED/UNDISPOSED


def build_model() -> Model:
    rows = parse_neg_rows(SMOKE_SH)
    names = all_case_names()
    positives = [n for n in names if not n.endswith("_neg")]
    fault_bases = {n[:-4] for n in names if n.endswith("_neg")}
    registry, reg_classes = load_registry()
    deferred = load_deferred()
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
    return Model(rows, positives, fault_bases, registry, reg_classes, deferred,
                 sound_cases, vacuous_cases, spurious_rows, disposition)


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

    # Every _neg mechanism must pair with a registered positive base and be able to
    # fail (a negative with no `fail` final catches nothing).
    for base in m.fault_bases:
        if base not in pos:
            findings.append(f"ORPHAN_NEG: {base}_neg has no registered positive base case")
        neg_rc = reason_classes(f"{base}_neg")
        if neg_rc is not None and not any("fail" in v for v in neg_rc.values()):
            findings.append(f"NEG_NO_FAIL: {base}_neg has no fail final; it cannot catch a fault")

    findings.extend(validate_registry(m.registry, m.reg_classes))
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--check", action="store_true", help="enforce the invariants (gate CI/pre-commit)")
    ap.add_argument("--write-ledger", action="store_true", help="regenerate the exhaustiveness ledger from the current UNDISPOSED set")
    args = ap.parse_args()

    m = build_model()
    undisposed = {c for c, d in m.disposition.items() if d == "UNDISPOSED"}

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
              f"_neg mechanisms: {len(m.fault_bases)}")
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
