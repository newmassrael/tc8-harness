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
pure function of the role:

| role | class | applies to |
|------|-------|------------|
| `conformant` | `pass` | required behaviour observed (role optional; `pass` is unambiguous) |
| `conformant_absence` | `pass` | "must NOT occur" assertion held: window elapsed, no prohibited event |
| `observed_violation` | `fail` | a captured frame/behaviour violates a MUST requirement |
| `precondition_unmet` | `inconclusive` | the IUT never reached the testable state — preamble incomplete (no OfferService, no initial ARP probe, no DUT-originated packet, no UT confirmation) |
| `property_unobserved` | `inconclusive` | the IUT reached the testable state (liveness shown), but the targeted frame/reaction was not observed within the window — **includes a mandated reaction that was not seen** |
| `test_system_fault` | `error` | the harness could not drive/observe: stimulus send failure, capture/socket failure, SCXML interpreter error, operator interruption |

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

## 6. OEM override & extension

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

## 7. Migration plan

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

## 8. Authorities

- ISO/IEC 9646-1, *Conformance testing methodology and framework — General
  concepts* (verdict definitions: pass / fail / inconclusive).
- ETSI ES 201 873-1 (TTCN-3 core language): the `error` verdict as a test-system
  condition.
- W3C SCXML 1.0 §5.5 (`<donedata>`): the per-case verdict carrier.
