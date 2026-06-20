# Conformance Verdict Policy (SSOT)

This document is the **single source of truth** for how the TC8 harness assigns
a conformance verdict to a test case. It is grounded in ISO/IEC 9646 (the OSI
Conformance Testing Methodology and Framework) and ETSI ES 201 873 (TTCN-3)
verdict semantics. Every `<final>` donedata authored in `tests/`, the
donedata-validity audit (`tools/verdict_drift_audit.py`), the runtime mapping in
`src/cli/test_command.cpp`, and the smoke gate (`dut/env/smoke-test.sh`) derive
their behaviour from this policy.

The policy is enforced mechanically (Section 5), not by per-case human judgement.
Authoring a verdict means choosing a **role** (Section 3); the **class** follows
from the role by the table below. A reviewer never re-litigates "fail vs
inconclusive" per case — the role decides.

---

## 1. The four verdict classes (taxonomy — fixed standard)

These are the ISO/IEC 9646 / TTCN-3 verdicts. They are an **immutable
conformance invariant**: an OEM may not redefine them, because doing so would
break comparability of results across implementations. `src/sce_integration/verdict.h`
is their single C++ definition; the Bash and Python mirrors are **generated**
from it (Section 5), never hand-copied.

| class | meaning | exit | reds the gate? |
|-------|---------|------|----------------|
| `pass` | The IUT exhibited the behaviour required by the test purpose — **observed**. | 0 | no |
| `fail` | The IUT exhibited behaviour that **violates** a MUST requirement — **observed** non-conformance. | 1 | yes |
| `inconclusive` | The IUT behaved validly, but the test purpose could not be decided (the targeted behaviour was neither confirmed nor refuted). | 2 | no |
| `error` | The **test system** could not drive or observe the IUT. Not a statement about the IUT. | 3 | no |
| `running` | Sentinel for a state carrying no donedata (an authoring defect). Fail-closed. | 1 | yes |

The decisive ISO 9646 / TTCN-3 distinction, which this project previously
conflated:

> **`error` is a property of the TEST SYSTEM, never of the IUT.** An IUT that
> fails to reach the state a test needs (no service offered, no ARP probe, no
> reply) has *not* malfunctioned the test system — the test simply could not be
> decided, which is **`inconclusive`**, not `error`. `error` is reserved for the
> harness itself failing: a stimulus that could not be sent, a capture that
> could not open, an interpreter fault, an operator interruption.

---

## 2. Verdict semantics (decision rule)

Read top to bottom; the first matching clause assigns the verdict.

1. **Observed a MUST violation** → `fail`. A frame or behaviour was captured
   that contradicts a normative requirement (wrong field, prohibited event in a
   forbidden window, malformed-but-accepted input).
2. **Observed the required conformant behaviour** → `pass`. Includes a
   *conformant absence*: a "must NOT occur" assertion whose observation window
   elapsed with no prohibited event.
3. **The test system failed** → `error`. The harness could not present the
   stimulus or observe the wire (see Section 3, `test_system_fault`).
4. **Otherwise the purpose could not be decided** → `inconclusive`. The IUT was
   not shown to violate anything and the required behaviour was not confirmed:
   the preamble did not complete, or the targeted frame/reaction was not
   observed within the window.

Soundness corollary: the gate (`fail`) fires **only** on clause 1 — an observed
violation. Environmental shortfalls never red the gate.

---

## 3. Semantic roles → class (the policy table)

Every non-`pass` `<final>` declares its **role** in donedata. The class is a
pure function of the role. This mapping is the single source
`src/sce_integration/verdict_taxonomy.def` and is regenerated into the table
below by `tools/gen_verdict_taxonomy.py` (CI fails if it drifts):

<!-- GENERATED:role-table BEGIN (gen_verdict_taxonomy.py) -->
| role | class |
|------|-------|
| `conformant` | `pass` |
| `conformant_absence` | `pass` |
| `observed_violation` | `fail` |
| `fault_injection_inert` | `fail` |
| `precondition_unmet` | `inconclusive` |
| `property_unobserved` | `inconclusive` |
| `test_system_fault` | `error` |
<!-- GENERATED:role-table END -->

Role meanings:
- **`conformant`** — required behaviour observed (role optional; `pass` is unambiguous).
- **`conformant_absence`** — "must NOT occur" assertion held: window elapsed, no prohibited event.
- **`observed_violation`** — a captured frame/behaviour violates a MUST requirement (the IUT is non-conformant).
- **`fault_injection_inert`** — a `_neg` self-validation case landed on its conformant-DUT (`fail_compliant*`) branch: the injected firmware fault produced no observable change, so the negative caught nothing. Same `fail` class (gate-red) as `observed_violation` but a distinct meaning — a fault-wiring / test-suite regression, **not** a DUT defect. See Section 6.1.
- **`precondition_unmet`** — the IUT never reached the testable state: preamble incomplete (no OfferService, no initial ARP probe, no DUT-originated packet, no UT confirmation).
- **`property_unobserved`** — the IUT reached the testable state (liveness shown), but the targeted frame/reaction was not observed within the window (**includes a mandated reaction that was not seen**).
- **`test_system_fault`** — the harness could not drive/observe: stimulus send failure, capture/socket failure, SCXML interpreter error, operator interruption.

The split between `precondition_unmet` and `property_unobserved` is **diagnostic
only** — both are `inconclusive`. It records *where* the test stalled (before vs
after liveness) in the reason string, without changing the class. This replaces
the previous (non-standard) practice of classifying preamble failure as `error`.

### Why "mandated reaction not observed" is `inconclusive`, not `fail`

A test that injects a stimulus (e.g. a conflicting ARP) and waits for a mandated
reaction (e.g. an address re-pick) assigns `inconclusive` when the reaction is
not seen, **not** `fail`. We did not *observe a violation*; we observed an
*absence*, and absence over a finite capture window cannot be distinguished from
a missed observation with certainty. Per clause 4, that is `inconclusive`. The
negative-test harness (which deliberately forces the reaction to be absent) is
what proves such a guard is non-vacuous; see Section 6.

---

## 4. Worked examples

| pattern | terminal condition | role | class |
|---------|--------------------|------|-------|
| RPC/SD field check | DUT never offered the service | `precondition_unmet` | inconclusive |
| RPC/SD field check | offered, but no matching response in window | `property_unobserved` | inconclusive |
| RPC/SD field check | response observed with wrong field | `observed_violation` | fail |
| FindService start-phase (ETS_099/100/101) | DUT emitted no SD at all | `precondition_unmet` | inconclusive |
| FindService start-phase | live, but FindService burst not seen | `property_unobserved` | inconclusive |
| FindService main-phase | a FindService appeared where forbidden | `observed_violation` | fail |
| FindService main-phase | window elapsed, none appeared | `conformant_absence` | pass |
| link-local conflict re-pick | DUT emitted no initial probe | `precondition_unmet` | inconclusive |
| link-local conflict re-pick | probed, but did not re-pick after conflict | `property_unobserved` | inconclusive |
| link-local probe field | probe observed with wrong field | `observed_violation` | fail |
| UDP UT received-check | no UT GetReceivedUdp confirmation | `precondition_unmet` | inconclusive |
| UDP UT received-check | confirmation seen, asserted field wrong | `observed_violation` | fail |
| any | harness `-t` budget elapsed before a verdict | `property_unobserved` | inconclusive |
| any | run interrupted (SIGINT/SIGTERM) | `test_system_fault` | error |

**Harness-synthesised verdicts** (`src/cli/test_command.cpp`, when the SCXML did
not reach a final): an operator **interruption** is a `test_system_fault` →
`error` (the test system was stopped externally and did not run to completion). A
**budget exceedance** is the harness `-t` backstop — for liveness/throughput
cases this is the deliberate observation bound, so reaching it means the purpose
could not be decided → `inconclusive` (`property_unobserved`). These are the only
two harness-synthesised cases; everything else comes from authored donedata.

---

## 5. Mechanism & enforcement

1. **Donedata carries the role.** Each non-`pass` final is authored as
   `{"verdict":"<class>","reason":"<reason>","role":"<role>"}`. The role is the
   stable *intent*; the class is the role's image under Section 3.
2. **The audit enforces `policy[role] == class`** for every final
   (`tools/verdict_drift_audit.py`), upgrading it from validity-only
   (is the class known?) to correctness (is the class right for the declared
   role?). A mismatch is a hard finding.
3. **Policy changes are mechanical.** Because role is the stable input, a change
   to the Section 3 table re-derives every class by script — no per-case hand
   edits. (This is what makes the A-semantics migration mechanical rather than
   535 individual judgements.)
4. **The taxonomy is generated, not mirrored.** `verdict.h` is the source; the
   Bash class list in `smoke-test.sh` and `VALID_CLASSES` in the audit are
   emitted from it by a build step. There is no hand-maintained second copy.
5. **The role→class table is machine-readable** so the audit and any codegen
   read one source (this document's table is the human view of it).

---

## 6. Negative-test strategy (suite self-validation)

A passing positive run shows the IUT *can* conform; it does not show the suite
would *catch* a non-conforming IUT. That second question — is each guard
non-vacuous, or does it pass regardless? — is **suite self-validation**, a form
of mutation analysis. How a guard's non-vacuity is established depends on **what
the guard compares**, and every case falls into exactly one of three strategies:

| strategy | the guard asserts | non-vacuity established by | recorded in |
|----------|-------------------|----------------------------|-------------|
| **expect-flip** | a captured field equals an *operator-supplied* value (`captured.X == expected.X`) | the **reference DUT** run with a deliberately-wrong `--expect` token → the guard must yield `observed_violation` | the curated `NEG_ROWS` set + `tools/negative_coverage_audit.py` |
| **dut-mutation** | *DUT behaviour* — it must reject malformed input, or must not emit a prohibited frame (`conformant_absence`) | a **faulty DUT** that actually misbehaves → the guard must yield `observed_violation`. No `--expect` flip can fault the conformant reference DUT | `tools/conformant_absence_registry.json` |
| **liveness** | the DUT must emit Y; Y is binary present/absent, no malformed variant | not applicable — absence is `inconclusive` (Section 2, clause 4); there is no reachable `fail` to validate | the same registry (`class: liveness`) |

The decisive separation: **`--expect` injection validates only expect-flip
guards.** A dut-mutation guard has no operator value to corrupt — the property is
a fact about the implementation, not about a configured expectation — so routing
it through the `--expect` ledger yields a *vacuous* negative: the injection
merely breaks a precondition and lands `inconclusive` (the `service_id=0x0000`
anti-pattern). Such a case therefore carries **no `NEG_ROWS` entry**. Its guard's
non-vacuity is **structural** — the `fail` `<final>` exists, is well-formed, and
is reachable by a misbehaving DUT — and is **empirical** only on the separate
DUT-mutation track.

The registry classifies each dut-mutation (and liveness) guard on a single axis —
the **property type**, i.e. which kind of fault trips its `fail` final — grounded
in the safety/liveness dichotomy and the four-value semantics of Section 2. Every
guard sorts by two mechanical questions: *(Q1)* is silence a conformant outcome
for this stimulus, and if not *(Q2)* does the mandated emission have a wrong-value
variant?

| registry `class` | conformant outcome | the `fail` fires on | mutant that trips it | examples |
|------------------|--------------------|--------------------|----------------------|----------|
| **`prohibited_emission`** (safety) | silence is conformant | a frame the protocol forbids here *appearing* | a DUT that emits the forbidden frame | reject malformed input (no OK echo); decline an invalid/unknown subscribe (no Ack); no emission after stop / in the wrong phase |
| **`incorrect_emission`** (functional) | a valued emission is mandated | that emission carrying a *wrong value* | a DUT that emits the right frame with a wrong value | ack (not nack) a valid subscribe; monotonic/wrapping session id; response-payload content; post-reset field value |
| **`liveness`** | an emission is mandated, binary present/absent | nothing — there is no `fail` (absence is `inconclusive`, Section 2 clause 4) | omission only, indistinguishable from slowness → not empirically faultable | DUT must emit an OfferService / a SYN-ACK |

`malformed_rejection` is the named case of `prohibited_emission` where the
forbidden frame is an OK echo of malformed input; the ISO 9646 stimulus class
(valid / invalid / inopportune) is descriptive context carried in each entry's
`property` string, not a separate axis.

Enforcement (`tools/negative_coverage_audit.py`) — **exhaustiveness**. Every
registered positive case must carry exactly one non-vacuity *disposition* that
proves its guard is checkable (ISO 9646 suite validation: a guard that can never
fire validates nothing):
- **`SOUND_ROW`** — a `NEG_ROWS` expect-flip negative whose expected `fail:<reason>`
  resolves to an `observed_violation` final (a conformant DUT, run with the wrong
  `--expect`, lands on `fail`).
- **`FAULT_INJECTION`** — a `<case>_neg` registered case drives a faulty DUT flavour
  to `fail` (the empirical DUT-mutation track, realised).
- **`REGISTRY`** — a `conformant_absence_registry.json` entry (a dut-behaviour
  guard, structurally non-vacuous, awaiting fault injection). Such a case carries
  **no** `NEG_ROWS` entry and no `_neg` sibling.
- **`DEFERRED`** — a `deferred_negatives.json` entry: an expect-flippable guard
  with no sound negative yet, each with an explicit reason (prefer fixing).

A positive case in none of these is **undisposed**; the exhaustiveness ledger
(`negative_coverage_undisposed.txt`) grandfathers today's backlog and `--check`
rejects any new undisposed case or stale ledger entry, forcing it to shrink to
zero — at which point every positive case is **covered** (accounted for by a
disposition). Coverage is not correctness: the gate proves every case *has* a
disposition, not that each disposition is genuine. It does close one correctness
hole mechanically — a `SOUND_ROW` must be a real value-flip, so a row that flips
an L3 source-IP filter (`ipv4`/`icmpv4` `dut_iface_ip`) and lands on an
absence/timeout `fail` is rejected as **spurious** (observation suppression, not a
faulted value). The rest is a review/empirical concern: a `REGISTRY` class and
property are reviewed; a `FAULT_INJECTION` pairing is grounded by the `_neg`
case's own green run; full empirical correctness is the Phase F track. The registry
is also structurally validated: every `fail` final is covered by a guard; a
non-`liveness` guard names a real `fail` final; a `liveness` guard names none and
the case has none.

Honesty boundary: the registry records *structural* non-vacuity and the
behavioural property each guard protects. **Empirical** validation of
dut-mutation guards — a mutant that trips each `fail` — is a distinct track, not
claimed by the `--expect` harness. Listing behavioural guards as `--expect`
"debt" conflates the two; this section removes that conflation.

### 6.1 Phase F — empirical verification (the standard, and its honest reach)

The exhaustiveness ledger is empty: every positive case carries a disposition, so
the suite is **covered**. The remaining frontier is **correctness** — proving each
*structural* (`REGISTRY`) guard actually fires by driving a faulty DUT onto its
`fail` final. This is mutation analysis / ISO 9646 suite validation, and it is the
**single** verification standard the suite converges to. The disposition taxonomy
above (four dispositions, three registry classes) is **frozen**: Phase F is
execution — producing `_neg` cases — not a re-cut of the model.

A `REGISTRY` guard is empirically faultable only when **both** hold: (a) the
misbehaviour can be *produced* — which depends on **who implements the protocol** —
and (b) the guard has a *reachable `fail`*. A `liveness` guard (Section 6, the
`liveness` row) maps absence to `inconclusive`, so it has no `fail` to drive and is
**never** promotable to `FAULT_INJECTION` on *any* DUT — it stays terminal in
`REGISTRY` by policy. The registry `class` is the SSOT for (b); `--phase-f` computes
the live split.

| DUT | protocols | faultable (`prohibited`/`incorrect`) | excluded from the target |
|-----|-----------|--------------------------------------|--------------------------|
| **tc8-dut firmware / vsomeip app** | ARP, IPv4 link-local, DHCPv4 client, SOME/IP (ETS + Server) | a `_neg` drives a firmware flavor onto the `fail` (the realised `ipv4_autoconf` pattern) — **the primary ratchet** | its `liveness` guards (no reachable `fail`) |
| **Linux kernel stack** | TCP, IPv4, ICMPv4, UDP | faultable only on the **lwIP DUT** (firmware stack) | against Linux the reference stack *is* the oracle; `liveness` likewise |

So the firmware ratchet targets the **faultable** (`prohibited` + `incorrect`)
guards, **not** every firmware guard: the `liveness` subset has no reachable `fail`
on any DUT, and counting it would set an unreachable goal. The kernel-stack guards
are faultable only on the lwIP track; against Linux they remain structural with the
reference stack as conformance oracle. Both exclusions are honest boundaries, not
gaps to paper over — `--phase-f` reports the live faultable target, its backlog, and
the excluded `liveness` and kernel buckets.

**Ratchet.** The primary metric flips from coverage (`undisposed → 0`, reached) to
empirical proof: the `FAULT_INJECTION` count is floored by
`negative_coverage_audit.py --check` and only ever rises as `_neg` cases land; the
current **faultable** `REGISTRY` set (`prohibited`/`incorrect`; `liveness` excluded)
is the work-list (`--phase-f`). Each `_neg` promotes a case `REGISTRY →
FAULT_INJECTION`.

**The `_neg` fail role.** A `_neg` reaches `pass` when it *observes the violation*
the injected fault produces, and `fail` (its `fail_compliant*` final) only when the
conformant DUT showed the correct behaviour **despite** the fault — i.e. the fault
was inert. That `fail` is gate-red, but it is **not** a DUT conformance violation:
it signals that the fault wiring (flavor plumbing, predicate, or stimulus) has
regressed and the negative no longer validates anything. Its role is therefore
`fault_injection_inert`, **not** `observed_violation` (which is reserved for an
actual IUT defect on a positive case). `negative_coverage_audit.py` pins every
`_neg` fail final to `fault_injection_inert` so this honest distinction cannot
silently regress.

---

## 7. OEM override & extension

The verdict subsystem is open along the **same compile-time, precedence-layered,
type-safe seams** the harness already uses for cases, capture filters, and
`--expect` tokens (`TC8_CASE_OVERRIDE_DIRS`/`TC8_EXTRA_CASE_DIRS`,
`kBpfExpression`, `applyExpectToken`). No parallel mechanism, and no
runtime-pluggable verdict logic (which would weaken conformance-evidence value —
the same boundary that keeps runtime SCXML loading out of tree).

| OEM intent | mechanism | status |
|------------|-----------|--------|
| **Override** a specific case's verdict | ship that case's `.scxml` (with its own donedata + role) via `TC8_CASE_OVERRIDE_DIRS`; audited against the policy | existing |
| **Extend** with new cases | `TC8_EXTRA_CASE_DIRS` | existing |
| **Extend** the role vocabulary | declare a new role mapped to **one of the four fixed classes** via the policy-extension seam (compile-time, OEM-namespaced, precedence OEM-over-standard, mirroring `kBpfExpression`) | to build |
| **Extend** reasons | OEM reason strings, validated by role | to build |
| Redefine the four classes / the standard role→class mappings | **not permitted** — conformance invariant | fixed |

The principle: an OEM may add their own cases, roles, and reasons, and may
override what verdict a *specific* case yields — but may **not** change what
`pass`/`fail`/`inconclusive`/`error` *mean* or how the standard roles map. That
fixity is exactly what makes the harness's results comparable and its
conformance evidence credible.

---

## 8. Migration plan

- **Phase 0 — this document.** Policy SSOT fixed and reviewed.
- **Phase 1 — foundation.** Generate the taxonomy mirrors from `verdict.h`
  (remove the hand copies); add the `role` field; extend the audit to enforce
  `policy[role] == class`.
- **Phase 2 — reconcile committed work to A.** Re-map preamble failures
  (`error_no_offer`, `error_no_dut_udp`, `error_no_dut_ipv4_packet`, …) from
  `error` to `inconclusive` (`precondition_unmet`) across SOMEIP_ETS_152, waves
  1–4, and this session's three commits. Reserve `error` for `test_system_fault`.
- **Phase 3 — mechanical migration.** Tag roles on the remaining binary
  deadline→fail cases and derive classes from the policy.
- **Phase 4 — honesty pass.** Make negative-row expectations declare their actual
  verdict; introduce the reason registry.

---

## 9. Authorities

- ISO/IEC 9646-1, *Conformance testing methodology and framework — General
  concepts* (verdict definitions: pass / fail / inconclusive).
- ETSI ES 201 873-1 (TTCN-3 core language): the `error` verdict as a test-system
  condition.
- W3C SCXML 1.0 §5.5 (`<donedata>`): the per-case verdict carrier.
