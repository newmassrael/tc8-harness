#!/usr/bin/env python3
"""Enforce negative-coverage EXHAUSTIVENESS + soundness (docs/verdict_policy.md
Section 6, debt D7).

Every registered positive conformance case must carry a non-vacuity DISPOSITION
that proves its verdict guard is checkable — that a non-conformant DUT would land
on `fail`. ISO 9646 suite validation / mutation analysis: a test whose guard can
never fire is vacuous and validates nothing. The four terminal dispositions are:

  SOUND_ROW        a negative row lands the conformant DUT on a `fail` final via
                   a deliberately-wrong --expect token (expect-flip negative).
                   The row is the inventory overrides' sixth axis
                   (docs/spec/inventory_overrides.json neg_wrong_token /
                   neg_expect_fail), applied by `tc8-harness --negative-row`;
                   rationale + which cases have none: dut/env/negative_rows.md.
  FAULT_INJECTION  a `<case>_neg` registered case drives a faulty DUT flavour to
                   `fail` (empirically verified — the Phase F north star, realised).
  REGISTRY         conformant_absence_registry.json — the guard asserts DUT
                   BEHAVIOUR (must emit a correct frame / must not emit a
                   prohibited one), which no --expect can fault; non-vacuity is
                   structural, awaiting a fault-injection negative.
  DEFERRED         deferred_negatives.json — an expect-flippable guard with no
                   sound negative yet, each carrying an explicit reason (Linux
                   deviation, needs-parameterise) until fixed.

A positive case in none of these is UNDISPOSED. A disposition names what the case
IS; it does not prove every guard in it. Exhaustiveness is therefore accounted per
`fail` final, the unit one negative run reaches (docs/tech-debt.md TD-42). A final
is PROVEN by any of:

  row       the case's sound row lands on it;
  neg       a `_neg` proves it -- mapped in fault_injection_coverage.json, or the
            lone `_neg` of a case with one `fail` final;
  registry  a conformant_absence_registry.json guard names it;
  deferred  deferred_negatives.json holds the case (every final), or holds
            `CASE:final` for that final of a SOUND_ROW case.

`registry` and `deferred` each claim to be the ONLY account of a final (a guard no
--expect can fault / a flippable guard with no negative yet), so either one beside
another mechanism on the same final is a contradiction. A row and a `_neg` may prove
the same final. A SOUND_ROW case may carry a PARTIAL registry entry or per-final
deferrals for the finals its row cannot reach; any other disposition keeps its own
completeness rule, because its label promises every final.

The exhaustiveness ledger (negative_coverage_undisposed.txt) holds the UNPROVEN
units: `case:final` for each fail final nothing proves, and a bare `case` for an
undisposed case with no fail final. It grandfathers today's set so the backlog is
retired incrementally; --check rejects any NEW unit and forces the ledger to shrink
as units are proven. When the ledger empties, every guard of every positive case is
*covered*.

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

Also enforced: registry structural validity (every `fail` final covered by a guard
unless the case is SOUND_ROW; declared classes; non-empty property), no final
proven by a contradicting pair (PROOF_CONFLICT), and NEG_ROW integrity (no STALE
row whose reason is not a final).

Default (no args): print the census. --check: enforce the invariants (gates
build-test.yml + pre-commit). --write-ledger: regenerate the exhaustiveness ledger
from the current unproven units (bootstrap / after a batch of dispositions).
--write-floor: record the current FAULT_INJECTION counts as the Phase F high-water
marks, one per fault DUT-layer (raise-only; run after a _neg lands).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
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

# The negative rows moved out of smoke-test.sh's NEG_ROWS array into the
# inventory overrides' sixth axis, so the harness can apply a row itself
# (`--negative-row`) and both drivers read one source instead of hand-mirroring
# the table. Read here as JSON rather than via `tc8-harness --list-neg-rows`
# deliberately: this audit is a pure-Python gate that must run in pre-commit
# without a build. Rationale + which cases have no row: dut/env/negative_rows.md.
OVERRIDES_JSON = REPO / "docs" / "spec" / "inventory_overrides.json"
HERE = Path(__file__).resolve().parent
LEDGER = HERE / "negative_coverage_undisposed.txt"
REGISTRY = HERE / "conformant_absence_registry.json"
DEFERRED = HERE / "deferred_negatives.json"
FAULT_COVERAGE = HERE / "fault_injection_coverage.json"
FLOOR_LEDGER = HERE / "fault_injection_floor.txt"

# Every per-platform overrides file. A `platform_known_fail_verdict` in one of these is
# a MEASURED claim that the named platform lands that verdict on that case, and a
# `fail:` one accounts for the named final: an unmodified DUT reaching it in a real run
# is stronger reachability evidence than any synthetic fault. Reachability is a property
# of the FINAL, not of a platform, so a claim on any file counts.
PLATFORM_OVERRIDES = (
    REPO / "docs" / "spec" / "inventory_overrides.json",
    REPO / "dut" / "lwip_dut" / "inventory_overrides.json",
)
# Where a lane that ASSERTS those claims has to live. The claims are only evidence while
# something re-measures them: `--exclude-platform-known-fail` drops these cases from the
# ordinary lanes, so without an asserting stage a registration keeps its entry after the
# platform is fixed and the account silently becomes a vacuous pass. This gate is the
# difference between "the mechanism exists" and "the mechanism is wired to the target".
WORKFLOWS_DIR = REPO / ".github" / "workflows"
# The verdict classes a `class:reason` token may name — the frozen 4-value model
# (docs/verdict_policy.md). `pass` is excluded on purpose: a known-fail mark records what
# the platform lands INSTEAD of passing, so a `pass:` verdict would be a contradiction in
# terms rather than a value to check.
VERDICT_CLASSES = frozenset({"fail", "inconclusive", "error"})

# A `_neg` case-name suffix: `_neg` for a single-guard case, or `_neg<n>`
# (`_neg2`, `_neg3`, ...) for one of several fault-injection variants of a
# multi-guard case (one per fail-final). Used to split positives from negatives
# and to derive the positive base a `_neg<n>` validates.
_NEG_RE = re.compile(r"_neg\d*$")

# The role every `_neg` fail final MUST carry. A `_neg` lands on `fail` only when
# the conformant DUT did NOT change behaviour under the injected fault — the fault
# was inert, a test-suite (fault-wiring) regression, NOT a DUT conformance
# violation. `observed_violation` would mislabel that as an IUT defect; the audit
# pins the honest role so a re-tagged or new `_neg` cannot silently regress it
# (docs/verdict_policy.md Section 6.1; verdict_taxonomy.def).
NEG_FAIL_ROLE = "fault_injection_inert"

# Token keys that are the L3 source-IP observation filter every guard conjuncts on.
# Flipping one suppresses observation entirely, so the case lands on an
# absence/timeout `fail` -- a SPURIOUS "sound" row that validates nothing. (The
# expected-VALUE keys `dut_iface_ip`/`arp.dut_iface_ip` are a different namespace
# and are genuine value flips.)
SPURIOUS_FILTER_KEYS = {"ipv4.dut_iface_ip", "icmpv4.dut_iface_ip"}

# Phase F (docs/verdict_policy.md Section 6.1): the empirical-verification ratchet.
# Coverage (undisposed -> 0) is reached; the live metric is now empirical proof.
# FAULT_INJECTION proofs only ever grow. The per-DUT-layer high-water marks are
# committed to FLOOR_LEDGER (not a hand-edited constant) and loaded by
# load_floors(); --check pins each live count to its mark, and --write-floor
# records new peaks (raise-only). The REGISTRY set is the work-list (--phase-f).

# A REGISTRY guard is empirically faultable only where the misbehaviour can be
# produced. Firmware families (tc8-dut / vsomeip app) take a _neg flavor case (the
# realised ipv4_autoconf pattern); kernel-stack families run against the Linux
# reference, which cannot be made to misbehave -- faultable only on the lwIP DUT,
# else structural with the reference stack as oracle. ARP is a kernel-stack family:
# the §4.2 ARP_xx guards observe frames the DUT's Linux neighbour layer emits
# (OpTriggerSendUdp provokes a cache-miss resolution; the kernel auto-replies for
# the DUT IP) -- tc8-dut builds no §4.2 ARP frame, so there is no flavor to inject.
# The only firmware ARP lives inside the link-local and DHCP-DAD flows, which are
# the IPV4_AUTOCONF / DHCPV4 families; §4.2 ARP is faultable only on the lwIP etharp
# stack. case_family matches the LONGEST family prefix (so IPV4_AUTOCONF beats the
# IPV4 prefix), independent of tuple order.
FIRMWARE_FAMILIES = ("IPV4_AUTOCONF", "DHCPV4", "SOMEIP_ETS", "SOMEIPSRV")
KERNEL_FAMILIES = ("ICMPV4", "TCP", "UDP", "IPV4", "ARP")

# Families longest-first so `c.startswith(fam)` resolves the most specific prefix
# (IPV4_AUTOCONF before IPV4) regardless of how the tuples above are ordered.
_FAMILIES_BY_LEN = tuple(sorted((*FIRMWARE_FAMILIES, *KERNEL_FAMILIES), key=len, reverse=True))

# The fault DUT-layers (Phase F ratchet keys), in ledger + report order: a tc8-dut
# firmware flavor mutant (FIRMWARE_FAMILIES) vs the lwIP fixture (KERNEL_FAMILIES).
# One named set so the floor round-trip, the --check lanes, and the report all
# iterate the SAME order.
FAULT_DUT_LAYERS = ("tc8_dut", "lwip")


def case_family(case_id: str) -> str:
    c = case_id.upper()
    for fam in _FAMILIES_BY_LEN:
        if c.startswith(fam):
            return fam
    return c.split("_")[0]


@dataclass(frozen=True)
class NegRow:
    case_id: str
    token: str
    exp_class: str
    exp_reason: str


def parse_neg_rows(overrides_path: Path) -> list[NegRow]:
    """Read the negative rows (the negative-set SSOT) from the inventory
    overrides' sixth axis. A case carries a row iff it sets `neg_wrong_token` +
    `neg_expect_fail`; both together or neither, which the harness's own loader
    also rejects — asserted here too so the gate fails on a half row rather than
    silently dropping the case's disposition to UNDISPOSED."""
    data = json.loads(overrides_path.read_text(encoding="utf-8"))
    rows: list[NegRow] = []
    for case_id, body in sorted(data.get("overrides", {}).items()):
        token = body.get("neg_wrong_token", "")
        expect = body.get("neg_expect_fail", "")
        if not token and not expect:
            continue
        if not token or not expect:
            raise SystemExit(
                f"negative_coverage_audit: {case_id} has half a negative row "
                "(neg_wrong_token and neg_expect_fail must be set together)"
            )
        exp_class, sep, exp_reason = expect.partition(":")
        if not sep or not exp_reason:
            raise SystemExit(
                f"negative_coverage_audit: {case_id} neg_expect_fail "
                f"{expect!r} is not <class>:<reason>"
            )
        rows.append(NegRow(case_id, token, exp_class, exp_reason))

        # EXTRA rows, for a case whose SCXML has more than one
        # expectation-graded fail final. Parallel arrays, mirroring the harness
        # loader; a length mismatch would pair a token with another row's verdict
        # and assert the wrong thing while looking authored, so it is refused
        # here as well as there (docs/tech-debt.md TD-53).
        extra_tokens = body.get("neg_extra_wrong_tokens", [])
        extra_expects = body.get("neg_extra_expect_fails", [])
        if len(extra_tokens) != len(extra_expects):
            raise SystemExit(
                f"negative_coverage_audit: {case_id} has {len(extra_tokens)} "
                f"neg_extra_wrong_tokens but {len(extra_expects)} "
                "neg_extra_expect_fails; they are parallel and must be the "
                "same length"
            )
        for extra_token, extra_expect in zip(extra_tokens, extra_expects):
            cls, sep2, reason = extra_expect.partition(":")
            if not sep2 or not reason:
                raise SystemExit(
                    f"negative_coverage_audit: {case_id} neg_extra_expect_fails "
                    f"{extra_expect!r} is not <class>:<reason>"
                )
            rows.append(NegRow(case_id, extra_token, cls, reason))
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


def fail_final_roles(case: str) -> dict[str, str]:
    """fail-final id (lowercased) -> declared role, for a case's .scxml
    (template-resolved exactly as codegen substitutes). Empty if no .scxml. Used
    to pin the role of `_neg` fail finals to NEG_FAIL_ROLE."""
    scxml = TESTS_DIR / case / f"{case}.scxml"
    if not scxml.is_file():
        return {}
    return {
        fid: role
        for fid, (cls, _reason, role) in extract_donedata(scxml).items()
        if cls == "fail"
    }


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


def split_unit(key: str) -> tuple[str, str | None]:
    """An accounting unit, as the ledger and deferred_negatives.json spell it:
    `CASE` -> (CASE, None), `CASE:final` -> (CASE, final)."""
    case, sep, final = key.partition(":")
    return case, (final if sep else None)


def load_known_fail_verdicts() -> dict[str, dict[str, str]]:
    """`case_lower -> {overrides-path-as-written: verdict}` for every platform overrides
    entry carrying a measured `platform_known_fail_verdict`. Read as JSON rather than via
    `tc8-harness --list-known-fails` for the same reason the rows are: this gate runs in
    pre-commit without a build."""
    out: dict[str, dict[str, str]] = {}
    for path in PLATFORM_OVERRIDES:
        if not path.is_file():
            continue
        rel = str(path.relative_to(REPO))
        data = json.loads(path.read_text(encoding="utf-8"))
        for case_id, body in (data.get("overrides") or {}).items():
            if not isinstance(body, dict):
                continue
            verdict = body.get("platform_known_fail_verdict", "")
            if verdict:
                out.setdefault(case_id.lower(), {})[rel] = verdict
    return out


def known_fail_lanes() -> set[str]:
    """The overrides files some workflow drives `--known-fail` against, as the paths those
    workflows name. A claim in a file NOT listed here is not re-measured by anything, so it
    may not account for a final -- see WORKFLOWS_DIR."""
    lanes: set[str] = set()
    if not WORKFLOWS_DIR.is_dir():
        return lanes
    for wf in sorted(WORKFLOWS_DIR.glob("*.yml")) + sorted(WORKFLOWS_DIR.glob("*.yaml")):
        text = wf.read_text(encoding="utf-8")
        if "--known-fail" not in text:
            continue
        for path in PLATFORM_OVERRIDES:
            rel = str(path.relative_to(REPO))
            if rel in text:
                lanes.add(rel)
    return lanes


def load_deferred() -> dict[str, str]:
    """deferred_negatives.json: unit -> reason, where a unit is a case_id (every
    final of the case) or `CASE:final` (one final of a SOUND_ROW case). An
    expect-flippable guard with no sound negative yet (Linux deviation,
    needs-parameterise). Empty if absent."""
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


def load_floors() -> dict[str, int]:
    """The committed Phase F high-water marks, one per fault DUT-layer: `tc8_dut`
    (firmware families, faulted by a tc8-dut flavor) and `lwip` (kernel families,
    faulted on the lwIP fixture). Missing key / absent file -> 0."""
    out = {d: 0 for d in FAULT_DUT_LAYERS}
    if not FLOOR_LEDGER.is_file():
        return out
    for line in FLOOR_LEDGER.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) == 2 and parts[0] in out:
            out[parts[0]] = int(parts[1])
    return out


def floor_ledger_text(marks: dict[str, int]) -> str:
    return (
        "# Phase F empirical-verification high-water marks (docs/verdict_policy.md\n"
        "# Section 6.1), one per fault DUT-layer: `tc8_dut` (firmware families, faulted\n"
        "# by a tc8-dut flavor) and `lwip` (kernel families, faulted on the lwIP etharp/\n"
        "# stack fixture). negative_coverage_audit.py --check fails if a live count drops\n"
        "# below its mark (a _neg was lost -- fix it) OR rises above it (a _neg landed --\n"
        "# run `--write-floor`). Monotonic: --write-floor only raises, never lowers, so a\n"
        "# regression on one DUT cannot be masked by a gain on the other.\n"
        + "".join(f"{d} {marks[d]}\n" for d in FAULT_DUT_LAYERS)
    )


def fault_by_dut(m: Model) -> dict[str, int]:
    """FAULT_INJECTION count split by the DUT-layer the fault is injected on:
    firmware families -> `tc8_dut` (a tc8-dut flavor drives the mutant), kernel
    families -> `lwip` (faulted on the lwIP fixture; the Linux reference is an
    oracle). Mirrors the FIRMWARE_FAMILIES / KERNEL_FAMILIES split."""
    fw = set(FIRMWARE_FAMILIES)
    out = {d: 0 for d in FAULT_DUT_LAYERS}
    for c, d in m.disposition.items():
        if d == "FAULT_INJECTION":
            out["tc8_dut" if case_family(c) in fw else "lwip"] += 1
    return out


def validate_registry(cases: dict[str, dict], classes: dict[str, str],
                      partial_ok: set[str] = frozenset()) -> list[str]:
    """Structural validation of each registry entry (docs/verdict_policy.md Section
    6). Each case carries a `guards` list — one guard per `fail` final (the exact
    unit a DUT-mutation mutant must trip), or a single `liveness` guard for a case
    with no `fail` final. Per guard: the class is declared; a non-`liveness` guard
    names a real `fail` final; a `liveness` guard names none and the case has no
    `fail` final; the `property` is non-empty. Completeness: every `fail` final is
    covered by a guard, except for a case in `partial_ok` (lower-case) -- a
    SOUND_ROW case, whose row already proves a final the registry must not name."""
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
        if missing and case_id.lower() not in partial_ok:
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
# authored class is correct. Each entry records why (reviewed,
# docs/verdict_policy.md Section 6).
CLASS_STRUCTURE_EXCEPTIONS = {
    "SOMEIP_ETS_096": "prohibited: forbidden SubscribeAck; PASS requires observing a NACK, so silence reaches inconclusive (not pass)",
    "ARP_39": "prohibited: forbidden UDP before the DUT's own ARP Request; PASS requires observing that Request, so silence reaches inconclusive (not pass)",
    "ARP_40": "prohibited: forbidden UDP before the DUT's own ARP Request; PASS requires observing that Request, so silence reaches inconclusive (not pass)",
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


def ledger_text(units: set[str]) -> str:
    header = (
        "# negative-coverage exhaustiveness ledger (debt D7 -- docs/verdict_policy.md\n"
        "# Section 6). Each line is one UNPROVEN unit: `case:final` for a `fail` final\n"
        "# of a positive case that no sound row, _neg, registry guard, measured\n"
        "# platform known-fail or deferral proves, or a bare `case` for an\n"
        "# undisposed case with no `fail` final.\n"
        "# Generated by tools/negative_coverage_audit.py --write-ledger.\n"
        "# Proving a unit (a sound row, a mapped _neg, a registry guard, a\n"
        "# platform_known_fail_verdict a lane asserts, or a\n"
        "# deferred_negatives.json entry) MUST delete its line here too; --check\n"
        "# fails on a new unproven unit or a stale (now-proven) entry. When this file\n"
        "# is empty every guard of every positive case is proven checkable.\n"
    )
    return header + "".join(f"{u}\n" for u in sorted(units))


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
    # case -> {overrides path as written: measured `class:reason` the platform lands}
    known_fail_verdicts: dict[str, dict[str, str]]
    # the overrides paths a workflow actually drives `--known-fail` against
    known_fail_lanes: set[str]
    # case -> {fail_reason: [mechanisms proving it]}; only cases with a fail final
    final_proofs: dict[str, dict[str, list[str]]] = field(default_factory=dict)


# The mechanisms that prove one fail final (module docstring). EXCLUSIVE ones claim
# to be the only account of their final, so they may not share it with another.
PROOF_ROW, PROOF_NEG, PROOF_REGISTRY, PROOF_DEFERRED = "row", "neg", "registry", "deferred"
PROOF_KNOWN_FAIL = "known_fail"
EXCLUSIVE_PROOFS = (PROOF_REGISTRY, PROOF_DEFERRED)


def compute_final_proofs(m: Model) -> dict[str, dict[str, list[str]]]:
    """For every positive case with a `fail` final, which mechanisms prove each
    final. A mechanism counts only where its link is real: a row only if SOUND
    (not spurious), a coverage mapping only to a registered `_neg` sibling of the
    case. Malformed links are reported by their own checks and prove nothing."""
    neg_set = set(m.neg_names)
    coverage = {b.lower(): mp for b, mp in m.fault_coverage.items()}
    registry = {k.lower(): e for k, e in m.registry.items()}
    spurious = {id(r) for r in m.spurious_rows}
    deferred_cases: set[str] = set()
    deferred_finals: dict[str, set[str]] = {}
    for key in m.deferred:
        case, final = split_unit(key)
        if final is None:
            deferred_cases.add(case.lower())
        else:
            deferred_finals.setdefault(case.lower(), set()).add(final)

    proofs: dict[str, dict[str, list[str]]] = {}
    for c in m.positives:
        finals = fail_reasons_of(c)
        if not finals:
            continue
        p: dict[str, list[str]] = {f: [] for f in sorted(finals)}
        for r in m.rows:
            if r.case_id.lower() == c and id(r) not in spurious and row_kind(r) == "SOUND":
                p[r.exp_reason].append(PROOF_ROW)
        if c in coverage:
            for reason, neg in coverage[c].items():
                neg_l = neg.lower()
                if reason in p and neg_l in neg_set and _NEG_RE.sub("", neg_l) == c:
                    p[reason].append(PROOF_NEG)
        elif c in m.fault_bases and len(finals) == 1:
            p[next(iter(finals))].append(PROOF_NEG)
        for g in registry.get(c, {}).get("guards", []):
            if g.get("fail_reason") in p:
                p[g["fail_reason"]].append(PROOF_REGISTRY)
        # A measured platform known-fail: the named platform lands this very final on an
        # UNMODIFIED DUT, which is the strongest reachability evidence of the five. Only a
        # `fail:` verdict counts -- an `inconclusive:` one says the guard was never
        # exercised and proves nothing about a fail final -- and only from a file some
        # lane actually asserts, or the claim is never re-measured and the account rots
        # into a vacuous pass the moment the platform is fixed.
        for rel, verdict in m.known_fail_verdicts.get(c, {}).items():
            if rel not in m.known_fail_lanes:
                continue
            cls, _, reason = verdict.partition(":")
            if cls == "fail" and reason in p:
                p[reason].append(PROOF_KNOWN_FAIL)
        for f in p:
            if c in deferred_cases or f in deferred_finals.get(c, ()):
                p[f].append(PROOF_DEFERRED)
        proofs[c] = p
    return proofs


def unproven_units(m: Model) -> set[str]:
    """The exhaustiveness ledger's units: `case:final` for each fail final no
    mechanism proves, and a bare `case` for an undisposed case with no fail final
    (its unit is the case itself)."""
    units: set[str] = set()
    for c in m.positives:
        finals = m.final_proofs.get(c)
        if finals is None:
            if m.disposition[c] == "UNDISPOSED":
                units.add(c)
            continue
        units.update(f"{c}:{f}" for f, mechs in finals.items() if not mechs)
    return units


def build_model() -> Model:
    rows = parse_neg_rows(OVERRIDES_JSON)
    names = all_case_names()
    neg_names = [n for n in names if _NEG_RE.search(n)]
    positives = [n for n in names if not _NEG_RE.search(n)]
    fault_bases = {_NEG_RE.sub("", n) for n in neg_names}
    registry, reg_classes = load_registry()
    deferred = load_deferred()
    fault_coverage = load_fault_coverage()
    reg_lower = {k.lower() for k in registry}
    # Only a case-level key disposes a case; a `CASE:final` key proves one final.
    def_lower = {k.lower() for k in deferred if split_unit(k)[1] is None}

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
    m = Model(rows, positives, neg_names, fault_bases, registry, reg_classes,
              deferred, fault_coverage, sound_cases, vacuous_cases, spurious_rows,
              disposition, load_known_fail_verdicts(), known_fail_lanes())
    m.final_proofs = compute_final_proofs(m)
    return m


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

    A SOUND_ROW case may carry a PARTIAL entry. Its disposition is its row, so no
    `_neg` promotes it and the completeness rule above has nothing to protect; an
    entry there records which of its finals a `_neg` proves because the row cannot
    -- a behaviour guard no --expect flip reaches (docs/tech-debt.md TD-41). Its
    keys must still be real fail finals and its values real `_neg` siblings, so the
    link is checked, not asserted. What proves a SOUND_ROW case's REMAINING finals
    is the per-final exhaustiveness rule's question (unproven_units), not this one.
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
        if m.disposition.get(base_l) == "SOUND_ROW":
            if not declared or not declared <= actual:
                findings.append(
                    f"FAULT_COVERAGE_INVALID: {base} (SOUND_ROW) coverage keys "
                    f"{sorted(declared - actual) or '[]'} are not .scxml fail-finals "
                    f"of the case (a partial entry names real finals only)"
                )
        elif declared != actual:
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
    pos = set(m.positives)

    # STALE rows: a row whose reason is not a final in the case.
    for r in m.rows:
        if row_kind(r) == "STALE":
            findings.append(f"STALE: {r.case_id} NEG_ROW reason '{r.exp_reason}' is not a final in the case")
        if row_kind(r) == "UNKNOWN":
            findings.append(f"UNKNOWN: {r.case_id} has no registered .scxml")

    # A known-fail mark must NAME what it suppresses, and the named thing has to exist.
    # Measured once already (docs/tech-debt.md TD-23): a mark was found suppressing an
    # INCONCLUSIVE rather than a FAIL — a category error the mark itself could not
    # express, because it carried no verdict at all. These three checks make the mark
    # say it.
    for c, per_file in sorted(m.known_fail_verdicts.items()):
        for rel, verdict in sorted(per_file.items()):
            cls, sep, reason = verdict.partition(":")
            if not sep or cls not in VERDICT_CLASSES:
                findings.append(
                    f"KNOWN_FAIL_MALFORMED: {c} in {rel} records '{verdict}', which is "
                    f"not a {'/'.join(sorted(VERDICT_CLASSES))} class:reason token"
                )
                continue
            if c not in pos:
                findings.append(f"KNOWN_FAIL_NOT_POSITIVE: {c} ({rel}) is not a registered positive case")
                continue
            if cls == "fail" and not fail_reasons_of(c):
                findings.append(
                    f"KNOWN_FAIL_NO_FAIL_FINAL: {c} ({rel}) records a fail verdict but the "
                    f"case has no fail final; it cannot be suppressing one"
                )
            elif cls == "fail" and reason not in fail_reasons_of(c):
                findings.append(
                    f"KNOWN_FAIL_STALE: {c} ({rel}) records 'fail:{reason}', which is not a "
                    f"fail final of the case"
                )

    # A registry case must be a positive. A FAULT_INJECTION case promises every
    # final is empirically proven, so a registry entry beside it contradicts the
    # label even where no fail final is shared (a liveness entry). Whether a guard
    # contradicts a row or a _neg on the SAME final is PROOF_CONFLICT's question.
    for c in reg_lower:
        if c not in pos:
            findings.append(f"REGISTRY_NOT_POSITIVE: {c} is not a registered positive case")
        elif m.disposition.get(c) == "FAULT_INJECTION":
            findings.append(f"REGISTRY_AND_FAULT: {c} has a _neg case (FAULT_INJECTION); drop the registry entry")

    # A case-level deferral must not also be disposed elsewhere; a per-final one
    # names a real fail final of a SOUND_ROW case (any other disposition either
    # proves every final or takes a case-level deferral).
    for key in m.deferred:
        case, final = split_unit(key)
        c = case.lower()
        if c not in pos:
            findings.append(f"DEFERRED_NOT_POSITIVE: {key} is not a registered positive case")
        elif final is None:
            if m.disposition.get(c) != "DEFERRED":
                findings.append(f"DEFERRED_REDUNDANT: {c} is already {m.disposition.get(c)}; drop the deferred entry")
        elif m.disposition.get(c) != "SOUND_ROW":
            findings.append(
                f"DEFERRED_INVALID: {key} defers one final of a {m.disposition.get(c)} case; "
                f"only a SOUND_ROW case takes a per-final deferral"
            )
        elif final not in fail_reasons_of(c):
            findings.append(f"DEFERRED_INVALID: {key} names a final that is not a fail final of the case")

    # An exclusive mechanism claims to be the only account of its final; beside any
    # other proof of the same final one of the two is wrong.
    #
    # A measured platform known-fail is the ONE exception, and only against a registry
    # guard. The two make compatible claims rather than competing ones: the guard says
    # the property is DUT BEHAVIOUR that no `--expect` value can fault, and a platform's
    # own defect landing that very final is DUT behaviour doing exactly what the guard
    # classifies. The known-fail CORROBORATES the entry instead of contradicting it, and
    # three finals on the lwIP fixture are in that state.
    #
    # Against a DEFERRAL it stays a conflict, and that asymmetry is the point: a deferral
    # says "this final has no account yet", which a measured landing directly refutes —
    # the deferral should be deleted, not kept beside it.
    for c, finals in sorted(m.final_proofs.items()):
        for f, mechs in finals.items():
            exclusive = [x for x in mechs if x in EXCLUSIVE_PROOFS]
            others = [x for x in mechs if x not in EXCLUSIVE_PROOFS]
            if exclusive == [PROOF_REGISTRY] and others == [PROOF_KNOWN_FAIL]:
                continue
            if len(mechs) > 1 and exclusive:
                findings.append(
                    f"PROOF_CONFLICT: {c}:{f} is proven by {sorted(mechs)}; a "
                    f"registry guard or deferral must be the final's only account"
                )

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
        # A _neg fail is the conformant-DUT branch (the fault was inert), not a DUT
        # violation: pin its role to NEG_FAIL_ROLE so the honest taxonomy cannot
        # silently regress to observed_violation.
        for fid, role in fail_final_roles(neg).items():
            if role != NEG_FAIL_ROLE:
                findings.append(
                    f"NEG_FAIL_ROLE: {neg} fail final '{fid}' role "
                    f"'{role or '(none)'}' must be '{NEG_FAIL_ROLE}' "
                    f"(a _neg fail is fault-injection-inert, not a DUT violation)"
                )

    sound_row = {c for c, d in m.disposition.items() if d == "SOUND_ROW"}
    findings.extend(validate_registry(m.registry, m.reg_classes, sound_row))
    findings.extend(check_class_structure(m.registry))
    findings.extend(validate_fault_coverage(m))

    # Phase F ratchet, per fault DUT-layer: each live FAULT_INJECTION count is pinned
    # to its committed high-water. Below = a _neg was lost (fix the code); above = a
    # _neg landed, peak not recorded (run --write-floor). Splitting by DUT stops a
    # regression on one (tc8_dut) being masked by a gain on the other (lwip).
    counts = fault_by_dut(m)
    floors = load_floors()
    for dut in FAULT_DUT_LAYERS:
        live, mark = counts[dut], floors[dut]
        if live < mark:
            findings.append(
                f"PHASE_F_REGRESSION: {dut} FAULT_INJECTION {live} < high-water "
                f"{mark}; a _neg case was lost (fix it, do NOT lower the ledger)"
            )
        elif live > mark:
            findings.append(
                f"PHASE_F_FLOOR_BEHIND: {dut} FAULT_INJECTION {live} > high-water "
                f"{mark}; a _neg landed -- run --write-floor and commit the ledger"
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
    """Phase F work-list (docs/verdict_policy.md Section 6.1): the two empirical-
    verification ratchets, one per fault DUT-layer. tc8-dut firmware (FIRMWARE_
    FAMILIES) is faulted by a flavor mutant; lwIP firmware (KERNEL_FAMILIES, where
    Linux is only an oracle) is faulted on the lwIP fixture. liveness guards (no
    reachable `fail`) are terminal by policy on both and excluded from the targets."""
    from collections import Counter
    fw_fams = set(FIRMWARE_FAMILIES)
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

    counts = fault_by_dut(m)
    floors = load_floors()
    print("Phase F -- empirical verification (docs/verdict_policy.md Section 6.1)")
    print("=" * 68)

    def ratchet(label, verified, backlog, mark):
        tgt = verified + len(backlog)
        pct = 100.0 * verified / tgt if tgt else 100.0
        print(f"  {label:38} (high-water {mark}): {verified}/{tgt} proven ({pct:.0f}%)")
        for fam, n in by_family(backlog):
            print(f"       {fam:14} {n}")

    ratchet("tc8-dut firmware [flavor mutant]", counts["tc8_dut"], fw_fault, floors["tc8_dut"])
    ratchet("lwIP firmware [etharp/stack fixture]", counts["lwip"], kn_fault, floors["lwip"])
    print(f"  -- liveness REGISTRY (no reachable fail; terminal by policy, NOT a target): "
          f"firmware {len(fw_live)} + kernel/lwIP {len(kn_live)} --")
    for fam, n in by_family(fw_live + kn_live):
        print(f"       {fam:14} {n}")
    return 0


def _self_test() -> int:
    """Prove the per-final rule fires. Mutates copies of the live model in memory
    (the .scxml finals are real; the registers are edited), so no fixture tree can
    drift from what --check reads."""
    import copy

    base = build_model()
    checks: list[tuple[str, bool]] = []

    def variant(mutate) -> tuple[set[str], list[str]]:
        m = copy.deepcopy(base)
        mutate(m)
        m.final_proofs = compute_final_proofs(m)
        return unproven_units(m), cross_findings(m)

    # A SOUND_ROW case with a final its row does not land on.
    row_of = {r.case_id.lower(): r for r in base.rows}
    case = next((c for c in sorted(base.sound_cases) if len(fail_reasons_of(c)) > 1), None)
    if case is None:
        print("self-test FAIL: no SOUND_ROW case with two fail finals to test on", file=sys.stderr)
        return 1
    row = row_of[case]
    other = sorted(fail_reasons_of(case) - {row.exp_reason})[0]
    unit = f"{case}:{other}"
    upper = row.case_id
    other_fi = next(c for c, d in sorted(base.disposition.items())
                    if d == "FAULT_INJECTION" and fail_reasons_of(c))

    def strip(m: Model) -> None:
        """Remove every non-row account of `other`, so only the row remains."""
        m.registry.pop(upper, None)
        m.deferred = {k: v for k, v in m.deferred.items() if split_unit(k)[0].lower() != case}
        m.fault_coverage = {b: mp for b, mp in m.fault_coverage.items() if b.lower() != case}

    def with_guard(reason: str):
        def mutate(m: Model) -> None:
            strip(m)
            m.registry[upper] = {"guards": [{"class": "prohibited_emission",
                                             "fail_reason": reason, "property": "p"}]}
        return mutate

    def with_deferral(key: str):
        def mutate(m: Model) -> None:
            strip(m)
            m.deferred[key] = "expect-flippable: self-test"
        return mutate

    u, _ = variant(strip)
    checks.append(("a final only the row misses is an unproven unit", unit in u))
    checks.append(("the row's own final is proven", f"{case}:{row.exp_reason}" not in u))

    u, f = variant(with_guard(other))
    checks.append(("a registry guard proves a SOUND_ROW final", unit not in u))
    checks.append(("a partial registry entry on a SOUND_ROW case is accepted",
                   not any(x.startswith("REGISTRY_INCOMPLETE") and upper in x for x in f)))

    _, f = variant(with_guard(row.exp_reason))
    checks.append(("a registry guard on the row's final conflicts",
                   any(x.startswith(f"PROOF_CONFLICT: {case}:{row.exp_reason}") for x in f)))

    u, _ = variant(with_deferral(f"{upper}:{other}"))
    checks.append(("a per-final deferral proves a SOUND_ROW final", unit not in u))

    _, f = variant(with_deferral(f"{upper}:{row.exp_reason}"))
    checks.append(("a deferral of the row's final conflicts",
                   any(x.startswith(f"PROOF_CONFLICT: {case}:{row.exp_reason}") for x in f)))

    # The measured platform known-fail mechanism. `lane` is whichever overrides file some
    # workflow actually drives --known-fail against; `dark` is one no lane asserts, which
    # is the whole soundness condition — an unasserted claim is never re-measured.
    lane = next(iter(sorted(base.known_fail_lanes)), None)
    # Deliberately NOT a repo-path-shaped string: the in-tree pointer gate reads this
    # file and a path-shaped literal that resolves nowhere is exactly what it rejects.
    # The mechanism compares plain strings against known_fail_lanes, so any non-member
    # value exercises it.
    dark = "(an overrides file no lane asserts)"

    def with_known_fail(verdict: str, in_file: str):
        def mutate(m: Model) -> None:
            strip(m)
            m.known_fail_verdicts[case] = {in_file: verdict}
        return mutate

    if lane is None:
        print("self-test FAIL: no workflow drives --known-fail against a platform "
              "overrides file, so the known-fail mechanism cannot be exercised",
              file=sys.stderr)
        return 1

    u, _ = variant(with_known_fail(f"fail:{other}", lane))
    checks.append(("a measured fail verdict from an asserted lane proves the final",
                   unit not in u))

    u, _ = variant(with_known_fail(f"inconclusive:{other}", lane))
    checks.append(("an inconclusive verdict proves nothing (the guard was never "
                   "exercised)", unit in u))

    u, _ = variant(with_known_fail(f"fail:{other}", dark))
    checks.append(("a verdict in a file no lane asserts proves nothing", unit in u))

    u, _ = variant(with_known_fail("fail:no_such_final", lane))
    checks.append(("a verdict naming a final the case does not have proves nothing",
                   unit in u))

    def guard_plus_known_fail(m: Model) -> None:
        with_guard(other)(m)
        m.known_fail_verdicts[case] = {lane: f"fail:{other}"}

    u, f = variant(guard_plus_known_fail)
    checks.append(("a known-fail CORROBORATES a registry guard rather than conflicting",
                   not any(x.startswith(f"PROOF_CONFLICT: {unit}") for x in f)))
    checks.append(("and the final stays proven", unit not in u))

    def deferral_plus_known_fail(m: Model) -> None:
        with_deferral(f"{upper}:{other}")(m)
        m.known_fail_verdicts[case] = {lane: f"fail:{other}"}

    _, f = variant(deferral_plus_known_fail)
    checks.append(("a known-fail CONTRADICTS a deferral, which claims no account exists",
                   any(x.startswith(f"PROOF_CONFLICT: {unit}") for x in f)))

    # The structural rules that make a mark NAME what it suppresses (TD-23).
    _, f = variant(with_known_fail("a bare reason with no class", lane))
    checks.append(("a verdict that is not a class:reason token is rejected",
                   any(x.startswith("KNOWN_FAIL_MALFORMED") for x in f)))

    _, f = variant(with_known_fail("fail:no_such_final", lane))
    checks.append(("a fail verdict naming a final the case lacks is rejected",
                   any(x.startswith("KNOWN_FAIL_STALE") for x in f)))

    def known_fail_on_a_neg(m: Model) -> None:
        strip(m)
        m.known_fail_verdicts[base.neg_names[0]] = {lane: f"fail:{other}"}

    _, f = variant(known_fail_on_a_neg)
    checks.append(("a known-fail mark on something that is not a positive case is rejected",
                   any(x.startswith("KNOWN_FAIL_NOT_POSITIVE") for x in f)))

    _, f = variant(with_deferral(f"{upper}:no_such_final"))
    checks.append(("a deferral of a missing final is rejected",
                   any(x.startswith("DEFERRED_INVALID") for x in f)))

    fi_key = f"{other_fi.upper()}:{sorted(fail_reasons_of(other_fi))[0]}"
    _, f = variant(lambda m: m.deferred.__setitem__(fi_key, "x"))
    checks.append(("a per-final deferral outside SOUND_ROW is rejected",
                   any(x.startswith(f"DEFERRED_INVALID: {fi_key}") for x in f)))

    live = next(c for c, e in sorted(base.registry.items()) if is_liveness_only(e))

    def undispose(m: Model) -> None:
        m.registry.pop(live)
        m.disposition[live.lower()] = "UNDISPOSED"
    u, _ = variant(undispose)
    checks.append(("an undisposed case with no fail final is a bare unit", live.lower() in u))

    failures = [label for label, ok in checks if not ok]
    for label in failures:
        print(f"self-test FAIL: {label}", file=sys.stderr)
    if failures:
        return 1
    print(f"negative_coverage_audit self-test: all {len(checks)} checks passed ({case})")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--check", action="store_true", help="enforce the invariants (gate CI/pre-commit)")
    ap.add_argument("--write-ledger", action="store_true", help="regenerate the exhaustiveness ledger from the current UNDISPOSED set")
    ap.add_argument("--write-floor", action="store_true", help="record the current FAULT_INJECTION count as the Phase F high-water mark (raise-only)")
    ap.add_argument("--phase-f", action="store_true", help="print the empirical-verification (fault-injection) work-list")
    ap.add_argument("--self-test", action="store_true", help="prove the per-final exhaustiveness rule fires")
    args = ap.parse_args()

    if args.self_test:
        return _self_test()

    m = build_model()
    unproven = unproven_units(m)
    n_finals = sum(len(f) for f in m.final_proofs.values())
    n_unproven_finals = sum(1 for u in unproven if split_unit(u)[1] is not None)

    if args.phase_f:
        return phase_f_report(m)

    if args.write_ledger:
        LEDGER.write_text(ledger_text(unproven), encoding="utf-8")
        print(f"wrote {LEDGER.relative_to(REPO)} ({len(unproven)} unproven)")
        return 0

    if args.write_floor:
        counts = fault_by_dut(m)
        floors = load_floors()
        lowered = [d for d in FAULT_DUT_LAYERS if counts[d] < floors[d]]
        if lowered:
            detail = ", ".join(f"{d} {floors[d]}->{counts[d]}" for d in lowered)
            print(
                f"refusing to lower the high-water ({detail}): a FAULT_INJECTION "
                f"drop is a regression to fix, not to record"
            )
            return 1
        FLOOR_LEDGER.write_text(floor_ledger_text(counts), encoding="utf-8")
        print(f"wrote {FLOOR_LEDGER.relative_to(REPO)} "
              f"(tc8_dut {counts['tc8_dut']}, lwip {counts['lwip']})")
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
        print(f"  neg rows: {len(m.rows)} ({len(m.sound_cases)} sound cases, "
              f"{len(m.vacuous_cases)} cases with only vacuous rows)")
        print(f"  registry: {len(m.registry)} | deferred: {len(m.deferred)} | "
              f"_neg mechanisms: {len(m.neg_names)} over {len(m.fault_bases)} bases")
        print(f"  fail finals: {n_finals} ({n_finals - n_unproven_finals} proven, "
              f"{n_unproven_finals} unproven)")
        print(f"  exhaustiveness ledger: {len(ledger)} entries  ({LEDGER.relative_to(REPO)})")
        for f in cross_findings(m):
            print(f"  {f}")
        new_debt = unproven - ledger
        gone = ledger - unproven
        if new_debt:
            print(f"  NEW unproven (not in ledger): {len(new_debt)} -> {sorted(new_debt)[:20]}")
        if gone:
            print(f"  ledger entries now proven (remove them): {len(gone)} -> {sorted(gone)[:20]}")
        return 0

    findings = cross_findings(m)
    for u in sorted(unproven - ledger):
        if split_unit(u)[1] is None:
            findings.append(f"NEW_UNDISPOSED: {u} has no non-vacuity disposition; add a sound row, register, _neg, or defer")
        else:
            findings.append(f"NEW_UNPROVEN_FINAL: {u} is proven by no row, _neg, registry guard or deferral")
    for u in sorted(ledger - unproven):
        findings.append(f"STALE_LEDGER: {u} is now proven; remove it from {LEDGER.name}")

    print(
        f"exhaustiveness: {counts.get('SOUND_ROW',0)} sound / {counts.get('FAULT_INJECTION',0)} fault-inj / "
        f"{counts.get('REGISTRY',0)} registry / {counts.get('DEFERRED',0)} deferred / "
        f"{counts.get('UNDISPOSED',0)} undisposed / {len(m.positives)} positive; "
        f"{n_unproven_finals}/{n_finals} fail finals unproven (ledger {len(ledger)})"
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
