#!/usr/bin/env python3
"""Enforce negative-test soundness (docs/verdict_policy.md §6, debt D7).

A negative test proves a positive guard is *non-vacuous*: that if the IUT were
non-conformant the case would land on `fail` (observed_violation). The harness
runs the (conformant) reference DUT with a deliberately-WRONG `--expect` token
and asserts the verdict is the expected `fail:<reason>` (dut/env/smoke-test.sh
`run_negative_case`). The curated set lives in the `NEG_ROWS` array there.

The 4-value verdict migration correctly reclassified "awaited observation absent
over a finite window" as `inconclusive` (not `fail`) — see docs/verdict_policy.md
§2 clause 4. The side effect: a negative whose injection merely *suppresses* the
awaited observation now lands on `inconclusive`, which `run_negative_case` routes
to the skip ledger. Such a row no longer verifies anything via `fail` — it is
VACUOUS. A sound negative must drive an *observed* violation.

This tool is the mechanical guard for that property. For every `NEG_ROWS` row it
resolves the case's donedata (reusing the template-aware extractor from
verdict_drift_audit) and classifies the row's expected `fail:<reason>` against
the case's finals:

  SOUND     the reason maps to a `fail`/observed_violation final  -> verify-via-fail intact
  VACUOUS   the reason maps to an `inconclusive` final            -> lands on skip, proves nothing
  STALE     the reason does not exist as any final in the case    -> dead row (typo/drift)
  UNKNOWN   the case_id has no registered .scxml

Ratchet (the `negative_coverage_baseline.txt` ledger). The VACUOUS set is large
today (debt D7 is being retired phase-by-phase). To be drift-proof from day one
without blocking CI on the whole backlog, `--check` enforces:

  1. STALE == 0 always (a row pointing at a non-existent reason is never ok).
  2. No VACUOUS row whose `case_id|reason` is absent from the baseline (a NEW
     vacuous negative is a regression — author a sound one instead).
  3. No baseline entry that is no longer VACUOUS (forces the ledger to shrink as
     cases are fixed: a fix commit removes the row's baseline entry too).

When the baseline empties, every negative is SOUND and condition 2/3 reduce to
"no VACUOUS rows at all" — the invariant is then fully enforced (Phase 5).

Conformant-absence (out of scope). Not every guard is expect-flippable: one that
asserts DUT BEHAVIOUR (must reject malformed input, must not emit a prohibited
frame) cannot be faulted by any `--expect` value, so an `--expect` negative for
it is inherently vacuous (docs/verdict_policy.md Section 6). Such cases carry NO
NEG_ROW; they are recorded in `conformant_absence_registry.json`, reported as
OUT_OF_SCOPE rather than debt, and their guards' non-vacuity is structural (the
named `fail` final exists), empirically provable only on the DUT-mutation track.
Each registry case lists `guards` — one per `fail` final (the unit a mutant must
trip) or a single `liveness` guard. `--check` enforces: each guard is structurally
valid (declared class; non-`liveness` names a real `fail` final; `liveness` names
none and the case has none; non-empty property); every `fail` final is covered by
a guard (a mixed-class case cannot be silently under-represented); and a registered
case carries no NEG_ROW.

Default (no args): print the full census. `--check`: enforce the ratchet (gates
build-test.yml + .githooks/pre-commit). `--write-baseline`: regenerate the
ledger from the current VACUOUS set (bootstrap / after a batch of fixes).
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
    extract_donedata,
)

SMOKE_SH = REPO / "dut" / "env" / "smoke-test.sh"
BASELINE = Path(__file__).resolve().parent / "negative_coverage_baseline.txt"
REGISTRY = Path(__file__).resolve().parent / "conformant_absence_registry.json"

# One `NEG_ROWS` entry: "CASE_ID|wrong_token|<class>:<reason>".
_ROW_RE = re.compile(r'"([^"|]+)\|([^"|]*)\|([a-z_]+):([^"]+)"')


@dataclass(frozen=True)
class NegRow:
    case_id: str
    token: str
    exp_class: str
    exp_reason: str

    @property
    def key(self) -> str:
        return f"{self.case_id}|{self.exp_reason}"


def parse_neg_rows(smoke_path: Path) -> list[NegRow]:
    """Extract the `NEG_ROWS=( ... )` array (the negative-set SSOT). Lines that
    are commented out (leading `#`) are skipped so example rows don't count."""
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


def reason_classes(case_id: str) -> dict[str, set[str]] | None:
    """reason -> {verdict classes that final carries}. None if no .scxml."""
    name = case_id.lower()
    scxml = TESTS_DIR / name / f"{name}.scxml"
    if not scxml.is_file():
        return None
    out: dict[str, set[str]] = {}
    for cls, reason, _role in extract_donedata(scxml).values():
        if reason:
            out.setdefault(reason, set()).add(cls)
    return out


def load_registry() -> tuple[dict[str, dict], dict[str, str]]:
    """The conformant-absence registry (docs/verdict_policy.md Section 6): cases
    whose guard is DUT-behaviour (dut-mutation strategy), out of scope for an
    `--expect` negative. Returns (cases, classes). Empty if the file is absent."""
    if not REGISTRY.is_file():
        return {}, {}
    data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    return data.get("cases", {}), data.get("classes", {})


def validate_registry(cases: dict[str, dict], classes: dict[str, str]) -> list[str]:
    """Structural validation of each registry entry (Section 6). Each case carries
    a `guards` list — one guard per `fail` final (the exact unit a DUT-mutation
    mutant must trip), or a single `liveness` guard for a case with no `fail`
    final. Per guard: the class is declared; a non-`liveness` guard names a real
    `fail` final; a `liveness` guard names none and the case has no `fail` final;
    the `property` is non-empty. Completeness: every `fail` final in the case is
    covered by a guard (so a case with mixed-class fail finals — e.g. one
    `prohibited_emission` and one `incorrect_emission` — cannot be silently
    under-represented by a single entry). Semantic correctness (is the property
    text accurate?) remains a review property."""
    findings: list[str] = []
    for case_id, entry in cases.items():
        guards = entry.get("guards")
        if not isinstance(guards, list) or not guards:
            findings.append(f"REGISTRY_INVALID: {case_id} has no guards list")
            continue
        rc = reason_classes(case_id)
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


def classify(row: NegRow) -> str:
    rc = reason_classes(row.case_id)
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


def load_baseline() -> set[str]:
    if not BASELINE.is_file():
        return set()
    out = set()
    for line in BASELINE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.add(line)
    return out


def baseline_text(keys: set[str]) -> str:
    header = (
        "# negative-coverage baseline ledger (debt D7 — docs/verdict_policy.md §6).\n"
        "# Each line is a `CASE_ID|reason` whose NEG_ROW currently lands on\n"
        "# `inconclusive` (VACUOUS — proves nothing via fail). Generated by\n"
        "# tools/negative_coverage_audit.py --write-baseline. A fix (re-role,\n"
        "# parameterize, re-point, or retire) MUST delete the row's line here too;\n"
        "# negative_coverage_audit.py --check fails on a stale or new entry.\n"
    )
    return header + "".join(f"{k}\n" for k in sorted(keys))


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--check", action="store_true", help="enforce the ratchet (gate CI/pre-commit)")
    ap.add_argument(
        "--write-baseline", action="store_true", help="regenerate the baseline ledger from current VACUOUS set"
    )
    args = ap.parse_args()

    rows = parse_neg_rows(SMOKE_SH)
    by_class: dict[str, list[NegRow]] = {}
    for row in rows:
        by_class.setdefault(classify(row), []).append(row)

    vacuous_keys = {r.key for r in by_class.get("VACUOUS", [])}

    registry, reg_classes = load_registry()
    registered = set(registry)
    registry_findings = validate_registry(registry, reg_classes)
    registered_with_row = sorted({r.case_id for r in rows if r.case_id in registered})

    if args.write_baseline:
        BASELINE.write_text(baseline_text(vacuous_keys), encoding="utf-8")
        print(f"wrote {BASELINE.relative_to(REPO)} ({len(vacuous_keys)} entries)")
        return 0

    baseline = load_baseline()

    if not args.check:
        print("negative-coverage census (NEG_ROWS = {} rows)".format(len(rows)))
        print("=" * 64)
        for kind in ("SOUND", "VACUOUS", "STALE", "UNKNOWN", "OTHER"):
            members = by_class.get(kind, [])
            print(f"  {kind:12} = {len(members)}")
        print(f"  {'OUT_OF_SCOPE':12} = {len(registry)}  (conformant-absence registry)")
        print("=" * 64)
        for kind in ("STALE", "UNKNOWN", "OTHER"):
            for r in by_class.get(kind, []):
                print(f"  {kind}: {r.case_id} -> {r.exp_class}:{r.exp_reason}")
        print(f"  baseline ledger: {len(baseline)} entries  ({BASELINE.relative_to(REPO)})")
        print(f"  conformant-absence registry: {len(registry)} entries  ({REGISTRY.relative_to(REPO)})")
        for f in registry_findings:
            print(f"  {f}")
        if registered_with_row:
            print(f"  registered cases that still carry a NEG_ROW (remove): {registered_with_row}")
        new_vac = vacuous_keys - baseline
        gone = baseline - vacuous_keys
        if new_vac:
            print(f"  NEW vacuous (not in baseline): {len(new_vac)} -> {sorted(new_vac)}")
        if gone:
            print(f"  baseline entries no longer vacuous (remove them): {len(gone)} -> {sorted(gone)}")
        return 0

    # --check: enforce the ratchet.
    findings: list[str] = []
    for r in by_class.get("STALE", []):
        findings.append(f"STALE: {r.case_id} NEG_ROW reason '{r.exp_reason}' is not a final in the case")
    for r in by_class.get("UNKNOWN", []):
        findings.append(f"UNKNOWN: {r.case_id} has no registered .scxml")
    for k in sorted(vacuous_keys - baseline):
        findings.append(f"NEW_VACUOUS: {k} lands on inconclusive; author a sound (observed_violation) negative")
    for k in sorted(baseline - vacuous_keys):
        findings.append(f"STALE_BASELINE: {k} is no longer vacuous; remove it from {BASELINE.name}")
    findings.extend(registry_findings)
    for cid in registered_with_row:
        findings.append(f"REGISTERED_WITH_ROW: {cid} is conformant-absence (registry); remove its NEG_ROW")

    sound = len(by_class.get("SOUND", []))
    print(
        f"negative-coverage: {sound} sound / {len(vacuous_keys)} vacuous (baseline {len(baseline)}) "
        f"/ {len(registry)} out-of-scope / {len(rows)} rows"
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
