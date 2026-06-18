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

Default (no args): print the full census. `--check`: enforce the ratchet (gates
build-test.yml + .githooks/pre-commit). `--write-baseline`: regenerate the
ledger from the current VACUOUS set (bootstrap / after a batch of fixes).
"""

from __future__ import annotations

import argparse
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
            print(f"  {kind:8} = {len(members)}")
        print("=" * 64)
        for kind in ("STALE", "UNKNOWN", "OTHER"):
            for r in by_class.get(kind, []):
                print(f"  {kind}: {r.case_id} -> {r.exp_class}:{r.exp_reason}")
        print(f"  baseline ledger: {len(baseline)} entries  ({BASELINE.relative_to(REPO)})")
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

    sound = len(by_class.get("SOUND", []))
    print(f"negative-coverage: {sound} sound / {len(vacuous_keys)} vacuous (baseline {len(baseline)}) / {len(rows)} rows")
    for f in findings:
        print(f"  {f}")
    if findings:
        print(f"FAIL: {len(findings)} finding(s)")
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
