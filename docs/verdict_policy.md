# Conformance Verdict Policy (SSOT)

This document is the **single source of truth** for how the TC8 harness assigns
a conformance verdict to a test case. It is grounded in ISO/IEC 9646 (the OSI
Conformance Testing Methodology and Framework) and ETSI ES 201 873 (TTCN-3)
verdict semantics. Every `<final>` donedata authored in `tests/`, the
donedata-validity audit (`tools/verdict_drift_audit.py`), the runtime mapping in
`src/cli/commands/test_command.cpp`, and the smoke gate
(`dut/env/orchestrator`) derive their behaviour from this policy.

The policy is enforced mechanically (Section 5), not by per-case human judgement.
Authoring a verdict means choosing a **role** (Section 3); the **class** follows
from the role by the table below. A reviewer never re-litigates "fail vs
inconclusive" per case — the role decides.

---

## 1. The four verdict classes (taxonomy — fixed standard)

These are the ISO/IEC 9646 / TTCN-3 verdicts. They are an **immutable
conformance invariant**: an OEM may not redefine them, because doing so would
break comparability of results across implementations.
`src/sce_integration/include/sce_integration/verdict.h` is their single C++
definition; the Bash and Python mirrors are **generated**
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

The four classes are verdicts, and a verdict is what a run returns. A case the
smoke gate could not dispatch (its DUT flavor refused, its conditioning failed,
the DUT or harness failed to spawn) returned none. It is not an `error`, and the
gate's non-conclusion ceiling does not apply to it: that ceiling tolerates a rate
of undecided verdicts, and a rate cannot tell a transient spawn fault from a
refusal that fails on every run. Any undispatched case reds the gate, the same way
a worker that dies before finishing its cases does (`docs/tech-debt.md` TD-59).

---

## 2. Verdict semantics (decision rule)

Read top to bottom; the first matching clause assigns the verdict.

1. **Observed a MUST violation** → `fail`. Either a frame or behaviour was
   captured that contradicts a normative requirement (wrong field, prohibited
   event in a forbidden window, malformed-but-accepted input), or **quiescence
   was observed where the requirement mandates an emission** (Section 2.1) —
   the DUT stayed silent over a valid observation window after the stimulus
   that obliges it to answer.
2. **Observed the required conformant behaviour** → `pass`. Includes a
   *conformant absence*: a "must NOT occur" assertion whose observation window
   elapsed with no prohibited event — itself an observation of quiescence, held
   to the same hypotheses as clause 1's (Section 2.1).
3. **The test system failed** → `error`. The harness could not present the
   stimulus or observe the wire (see Section 3, `test_system_fault`).
4. **Otherwise the purpose could not be decided** → `inconclusive`. The IUT was
   not shown to violate anything and the required behaviour was not confirmed:
   the preamble did not complete, or an absence decided the run while one of
   the quiescence hypotheses was not established.

Soundness corollary: the gate (`fail`) fires **only** on clause 1 — an observed
violation, of which observed quiescence is one kind. An absence counts as an
observation only when the run proved it could have seen the emission; when it
could not, the absence is a non-conclusion, never a `fail` and never a `pass`.
Environmental shortfalls never red the gate.

### 2.1 Quiescence and the test hypotheses

> **Status (Phase Q, Section 8).** Q1–Q3 are in the tree: the
> `observed_quiescence` role, its reach and bound rules, and the run-time gate on
> S, H1, H2 and H3. Q4 (migrating the `liveness` guards) is complete: the
> ledger is empty.

**Quiescence is an observation.** In the input/output conformance theory the
suite is grounded in (ioco, Tretmans), the absence of any output — quiescence,
δ — is an observable outcome of the IUT, on a par with an output frame. A
specification that obliges an emission after a stimulus does not admit δ there,
so observing δ is a non-conformance; a specification that forbids an emission
admits only δ, so observing δ is conformance. In real time δ is observed as "no
such output within a bound M" (timed ioco), and that observation is valid only
when M is not shorter than the time the specification grants the IUT.

So one primitive decides both directions: **a conclusive verdict decided by a
timer is an observation of quiescence.** A `conformant_absence` pass and an
`observed_quiescence` fail make the same claim about the wire and need the same
evidence. What that evidence is, is the set of test hypotheses below. ISO/IEC
9646 places a hypothesis about the test system outside the IUT's verdict: if it
does not hold, the run says nothing about the IUT.

| | hypothesis | established by | if not established |
|---|---|---|---|
| **S** | the stimulus that obliges or forbids the emission was performed | the unperformed-stimulus record (`tc8::UnperformedStimulus`) | `inconclusive`, reason names the stimulus |
| **H1** | the IUT was live and able to answer through the window's end | a **liveness anchor**: after the window, an exchange the IUT must answer, chosen to be independent of the requirement under test, answered on the wire | `inconclusive`, `liveness_anchor_*` reason |
| **H2** | the observation channel saw the whole window | capture completeness: no ring or interface drop, no snaplen truncation, every multicast group held (`tc8::captureProvenComplete`) | `inconclusive`, `capture_*` reason |
| **H3** | the window M is not shorter than the bound the requirement grants the IUT | the deciding final declares its bound in donedata — `"bound":"ParamListenTime"` (the tester's IXIT, default 10 s, set per run with `--expect ixit.param_listen_time_ms=`) or a literal `"<n>ms"` / `"<n>s"` the requirement states — and the run **measures** the window it closed | `inconclusive`, `window_shorter_than_bound` / `absence_bound_*` reason; the audit also rejects a window shorter than its bound at the default IXIT |

**Where each is enforced.**
- S, H1 and H2 are run facts. They are enforced in one place, the CLI's verdict
  qualification (`src/cli/commands/test_command.cpp`), for every verdict that
  claims an absence: a `pass` whose final transition was not driven by a frame
  (conservatively — a `pass` evaluated from a state query is checked too, which
  can only cost a conclusion, never forge one), and a `fail` whose role is
  `observed_quiescence` or, on a `_neg`, a timer-reached `fault_injection_inert`
  ("the DUT stayed silent despite the fault" is a quiescence claim too). Case
  authors never re-state them; an invariant handed to every author is one that
  gets forgotten.
- H3 is enforced twice. At run time, by the same qualification: the window is the
  deciding transition's source-state dwell (`ITestRunner::finalWindowUs`) — a
  measurement that can only read short of the timer that ran, so its error costs
  a conclusion and never forges one — compared with the bound resolved through
  the run's IXIT values. Statically, by the donedata audit
  (`tools/verdict_drift_audit.py`): an `observed_quiescence` final must declare a
  bound, and every window timer deciding it must be at least that long at the
  default IXIT. An operator who raises `ParamListenTime` above a case's window gets
  `inconclusive` from that case, not a `fail` for a DUT it allowed more time.
- An absence `pass` is held to a bound only when its final declares one. Declaring
  it is part of migrating the case (Phase Q4); until then such a pass is judged
  under S, H1 and H2 alone.

**The anchor.** Two kinds, run by the harness after the window on a capture
handle of their own (the case's filter often keeps their answer out, and widening
it would change what the machine saw in the window): an ARP Request for the DUT's
address, and an ICMP Echo Request to it, each answered within a bound and tried
twice. Any answered anchor establishes H1, so the choice never makes a verdict
unsound. What the choice decides is **power**: an anchor that runs through the
requirement under test goes unanswered by a DUT that violates that requirement
wholesale — a DUT whose ARP responder is broken fails an ARP anchor too — and the
case can then only report `inconclusive` about the very DUT it exists to fail. A
`_neg` is the sharp form: its fault suppresses the emission, and an anchor the
fault also suppresses leaves the `_neg` unable to pass. So each case declares the
requirements it grades as tags (`kRequirementsUnderTest`; a `_neg` and an alias
read through to the case they stand for; otherwise the family's broad default),
each anchor kind declares the requirements it exercises, and the harness takes
the kind sharing fewest with the case. The run prints how many it shares.

**Preamble versus test body.** The hypotheses decide only absences in the test
body: the IUT has reached the testable state and the stimulus under test has
been applied. A preamble that never completes (the DUT never offered the service,
never probed its address) is `precondition_unmet` → `inconclusive` whatever the
hypotheses say, because the test purpose was never exercised. This is the TTCN-3
convention: a timeout in the preamble is inconclusive, a timeout on a mandated
reply in the test body is a fail.

**Frame-decided verdicts are unaffected.** A verdict whose final transition was
driven by a captured frame carries its own evidence in the trace; no hypothesis
about absence applies to it.

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
| `observed_quiescence` | `fail` |
| `fault_injection_inert` | `fail` |
| `precondition_unmet` | `inconclusive` |
| `property_unobserved` | `inconclusive` |
| `test_system_fault` | `error` |
<!-- GENERATED:role-table END -->

Role meanings:
- **`conformant`** — required behaviour observed (role optional; `pass` is unambiguous).
- **`conformant_absence`** — "must NOT occur" assertion held: window elapsed, no prohibited event.
- **`observed_violation`** — a captured frame/behaviour violates a MUST requirement (the IUT is non-conformant).
- **`observed_quiescence`** — the IUT stayed silent over the test-body window where a MUST requirement obliges it to emit (Section 2.1). The CLI keeps it a `fail` only while S, H1 and H2 hold, and downgrades it to `inconclusive` naming the missing hypothesis otherwise. Its decisive evidence is an absence, so it is reachable only through a **window timer** (an event the machine raises itself with a non-zero `delay`), never through a frame and never only through a zero-delay evaluation step. A `fail` that a timer reaches but whose evidence is a captured value or a state query (an RTO measured from frames, a `TCP_INFO` counter) is an `observed_violation`: the timer only says when to evaluate.
- **`fault_injection_inert`** — a `_neg` self-validation case landed on its conformant-DUT (`fail_compliant*`) branch: the injected firmware fault produced no observable change, so the negative caught nothing. Same `fail` class (gate-red) as `observed_violation` but a distinct meaning — a fault-wiring / test-suite regression, **not** a DUT defect. See Section 6.1.
- **`precondition_unmet`** — the IUT never reached the testable state: preamble incomplete (no OfferService, no initial ARP probe, no DUT-originated packet, no UT confirmation).
- **`property_unobserved`** — the IUT reached the testable state, but the targeted frame/reaction was not observed and the absence could not be graded: a quiescence hypothesis was not established, or the case has not yet been migrated to `observed_quiescence` (Section 8, Phase Q). It is also what the CLI's downgrade of a timer-decided verdict reports.
- **`test_system_fault`** — the harness could not drive/observe: stimulus send failure, capture/socket failure, SCXML interpreter error, operator interruption.

The split between `precondition_unmet` and `property_unobserved` is **diagnostic
only** — both are `inconclusive`. It records *where* the test stalled (before vs
after liveness) in the reason string, without changing the class. This replaces
the previous (non-standard) practice of classifying preamble failure as `error`.

### When a mandated reaction that was not observed is a `fail`

An earlier revision of this policy graded every unseen mandated reaction
`inconclusive`, on the ground that an absence over a finite window cannot be told
from a missed observation. The ground is right and the conclusion was not: it
names a property of the **test system** (could the capture have missed it? was
the DUT up?), and ISO/IEC 9646 keeps such properties out of the IUT's verdict by
stating them as test hypotheses and checking them, not by lowering every absence
to a non-conclusion. Lowering them also left the suite unable to fail a DUT that
never answers, and graded the same observation two ways — a silent window was a
`pass` for a "must not send" case without any check that the DUT was alive.

So an unseen mandated reaction in the test body is `observed_quiescence` → `fail`
when the run establishes S, H1 and H2 and the case satisfies H3 (Section 2.1),
and `inconclusive` naming the missing hypothesis when it does not. The same
hypotheses now gate every `conformant_absence` pass.

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
| FindService main-phase | window elapsed, none appeared, S/H1/H2 established | `conformant_absence` | pass |
| FindService main-phase | window elapsed, none appeared, liveness anchor unanswered | (CLI downgrade) | inconclusive |
| ARP Request reception | well-formed Request applied, no Reply in a valid window, anchor answered | `observed_quiescence` | fail |
| ARP Request reception | no Reply, and the anchor was not answered either | (CLI downgrade) | inconclusive |
| link-local conflict re-pick | DUT emitted no initial probe | `precondition_unmet` | inconclusive |
| link-local conflict re-pick | probed, but did not re-pick after conflict | `property_unobserved` | inconclusive |
| link-local probe field | probe observed with wrong field | `observed_violation` | fail |
| UDP UT received-check | no UT GetReceivedUdp confirmation | `precondition_unmet` | inconclusive |
| UDP UT received-check | confirmation seen, asserted field wrong | `observed_violation` | fail |
| any | harness `-t` budget elapsed before a verdict | `property_unobserved` | inconclusive |
| any | run interrupted (SIGINT/SIGTERM) | `test_system_fault` | error |

**Harness-synthesised verdicts** (`src/cli/commands/test_command.cpp`, when the SCXML did
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
| **dut-mutation (required emission)** | the DUT must emit Y; Y is binary present/absent, no malformed variant | a **faulty DUT** that omits Y → the guard must yield `observed_quiescence` (Section 2.1) | the same registry (`class: required_emission`) |

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
| **`required_emission`** (liveness) | an emission is mandated, binary present/absent | its *absence* over a valid window — `observed_quiescence` | a DUT that omits the emission; slowness is excluded by H3, so the omission is faultable | DUT must emit an OfferService / a SYN-ACK / an ARP Reply |

**`liveness`** is the transitional name of a `required_emission` guard whose case
has not yet been migrated (Section 8, Phase Q): its absence still lands on an
`inconclusive` final, so it has no `fail` and is not faultable until it moves. The
audit accepts it only from the migration ledger, which may only shrink.

**`optional_emission`** is the guard of a case whose behaviour a conformant DUT may
omit: a MAY, or a duty the normative sources disagree on. In ioco terms quiescence
is among the specified outputs after the stimulus, so no test can fail on it; the
case passes when the behaviour is shown and is `inconclusive`
(`property_unobserved`) when it is not. The guard names no `fail` final, cites the
requirement id that makes the behaviour optional (`basis`), and names the
inconclusive final its case lands on without it (`absence_reason`). It is
permanent, unlike `liveness`, and not faultable. A choice between permitted
responses is not this class: where the requirement is "one of (a) or (b)", silence
answers neither and is a `required_emission` fail, and the permitted branch the
case does not exercise is `inconclusive` (`IPv4_AUTOCONF_CONFLICT_10`).

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
  guard, structurally non-vacuous, awaiting fault injection). Such a case has no
  `_neg` sibling.
- **`DEFERRED`** — a `deferred_negatives.json` entry: an expect-flippable guard
  with no sound negative yet, each with an explicit reason (prefer fixing).

A positive case in none of these is **undisposed**. A disposition labels the case;
it does not prove every guard in it, because one negative run reaches one `fail`
final. So exhaustiveness is counted **per `fail` final**. A final is proven by the
case's sound row landing on it, by a `_neg` mapped to it in
`fault_injection_coverage.json` (or the lone `_neg` of a one-final case), by a
registry guard naming it, or by a deferral. A `SOUND_ROW` case whose row cannot
reach some finals may take a partial registry entry or `CASE:final` deferrals for
them. A registry guard or deferral must be the only account of its final: beside a
row or a `_neg` on the same final it contradicts them. The exhaustiveness ledger
(`negative_coverage_undisposed.txt`) holds each unproven final as `case:final` (a
bare `case` for an undisposed case with no `fail` final). `--check` rejects any
new unit or stale ledger entry, forcing the ledger to shrink to zero — at which
point every guard of every positive case is **covered**. Coverage is not correctness: the gate proves every case *has* a
disposition, not that each disposition is genuine. It does close one correctness
hole mechanically — a `SOUND_ROW` must be a real value-flip, so a row that flips
an L3 source-IP filter (`ipv4`/`icmpv4` `dut_iface_ip`) and lands on an
absence/timeout `fail` is rejected as **spurious** (observation suppression, not a
faulted value). The rest is a review/empirical concern: a `REGISTRY` class and
property are reviewed; a `FAULT_INJECTION` pairing is grounded by the `_neg`
case's own green run; full empirical correctness is the Phase F track. The registry
is also structurally validated: every `fail` final is covered by a guard; a
non-`liveness` guard names a real `fail` final; a `required_emission` guard's final
carries the `observed_quiescence` role and declares its H3 bound; a transitional
`liveness` guard names none, the case has none, and the case is on the migration
ledger; an `optional_emission` guard names none, cites a requirement id, and names
a `property_unobserved` final of its case.

Honesty boundary: the registry records *structural* non-vacuity and the
behavioural property each guard protects. **Empirical** validation of
dut-mutation guards — a mutant that trips each `fail` — is a distinct track, not
claimed by the `--expect` harness. Listing behavioural guards as `--expect`
"debt" conflates the two; this section removes that conflation.

### 6.1 Phase F — empirical verification (the standard, and its honest reach)

Every positive case carries a disposition. Counted per `fail` final, coverage is
not complete: the exhaustiveness ledger lists the finals of `SOUND_ROW` cases that
their row does not reach and nothing else proves. `negative_coverage_audit.py`
prints the live count. The other frontier is **correctness** — proving each
*structural* (`REGISTRY`) guard actually fires by driving a faulty DUT onto its
`fail` final. This is mutation analysis / ISO 9646 suite validation, and it is the
**single** verification standard the suite converges to. The disposition taxonomy
above (four dispositions, three registry classes) is **frozen**: Phase F is
execution — producing `_neg` cases — not a re-cut of the model. (The one re-cut
since, Section 2.1, renamed nothing and removed nothing: it gave the third class a
reachable `fail`.)

A `REGISTRY` guard is empirically faultable only when **both** hold: (a) the
misbehaviour can be *produced* — which depends on **who implements the protocol** —
and (b) the guard has a *reachable `fail`*. A `required_emission` guard has one —
its `observed_quiescence` final — so it is faultable like the other two classes:
its `_neg` arms a flavor that suppresses the emission and grades `pass` on the
quiescence it causes. Only a transitional `liveness` guard (not yet migrated) still
lacks a `fail` and stays out of the target until it moves. The registry `class` is
the SSOT for (b); the family→DUT
mapping (a) lives in `negative_coverage_audit.py`
(`FIRMWARE_FAMILIES`/`KERNEL_FAMILIES`), which the table below only mirrors;
`--phase-f` computes the live split and is authoritative.

| DUT | protocols | faultable (`prohibited`/`incorrect`/`required_emission`) | excluded from the target |
|-----|-----------|--------------------------------------|--------------------------|
| **tc8-dut firmware / vsomeip app** | IPv4 link-local, DHCPv4 client, SOME/IP (ETS + Server) | a `_neg` drives a firmware flavor onto the `fail` (the realised `ipv4_autoconf` pattern) — **the primary ratchet** | its unmigrated `liveness` guards (no reachable `fail` yet) |
| **Linux kernel stack** | TCP, IPv4, ICMPv4, UDP, ARP (§4.2) | faultable only on the **lwIP DUT** (firmware stack) | against Linux the reference stack *is* the oracle; unmigrated `liveness` likewise |

So the firmware ratchet targets the **faultable** guards, **not** every firmware
guard: an unmigrated `liveness` guard has no reachable `fail` on any DUT, and
counting it would set an unreachable goal. The kernel-stack guards
are faultable only on the lwIP track; against Linux they remain structural with the
reference stack as conformance oracle. **§4.2 ARP** sits in this kernel-stack row,
not with the firmware families: the DUT emits no §4.2 ARP frame itself —
`OpTriggerSendUdp` provokes a cache-miss the Linux neighbour layer resolves, and the
kernel auto-replies for the DUT IP, so there is no tc8-dut flavor to inject. The
firmware ARP the DUT *does* build belongs to the link-local and DHCP-DAD flows,
counted under those families. Both exclusions are honest boundaries, not
gaps to paper over — `--phase-f` reports the live faultable target, its backlog, and
the excluded `liveness` and kernel buckets.

**Ratchet.** Beside per-final coverage (the ledger shrinking to zero), the metric
is empirical proof: the `FAULT_INJECTION` count is floored by
`negative_coverage_audit.py --check` and only ever rises as `_neg` cases land; the
current **faultable** `REGISTRY` set (`prohibited`/`incorrect`/`required_emission`; unmigrated `liveness` excluded)
is the work-list (`--phase-f`). Each `_neg` promotes a case `REGISTRY →
FAULT_INJECTION`. The ratchet is **per fault DUT-layer** — one high-water for
`tc8_dut` (firmware families, a flavor mutant) and one for `lwip` (kernel families,
faulted on the lwIP fixture), committed to `tools/fault_injection_floor.txt`. They
are floored independently so a regression on one cannot be masked by a gain on the
other, and `--write-floor` only ever raises a mark, never lowers it (a drop is a
regression to fix, not to record). `--phase-f` reports both ratchets and their
backlogs.

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

### Phase Q — quiescence as an observation (Section 2.1)

Each step lands with its own gate, so the policy text never claims a mechanism the
tree does not have.

- **Q1 — vocabulary and the authoring rule.** The `observed_quiescence` role. The
  donedata audit learns which events of the composed machine (case plus bound
  templates) are window timers — raised by its own `<send>` with a non-zero
  `delay` — and enforces Section 3: an `observed_quiescence` final is reached only
  through window timers. Measured when the rule was written: of 766 `fail` finals,
  659 are reached by frames and 107 by timers (83 `_neg` inert finals, and 24
  positive value judgments evaluated on a zero-delay step or at a window's end,
  all correctly `observed_violation`); none is reached by an eventless or raised
  transition.
- **Q2 — the hypotheses at run time.** The liveness anchor (two kinds: an ARP
  exchange and an ICMP Echo exchange, each declaring the requirements it
  exercises), the requirement tags a case declares (a per-family default,
  narrowed per case), and the CLI qualification extended from "a timer-decided
  `pass` needs H2 and S" to "**every** timer-decided conclusive verdict — `pass`
  or `fail`, positive or `_neg` — needs S, H1 and H2". This is the step that also
  tightens every existing `conformant_absence` pass: a dead DUT no longer passes
  a "must not send" case.
- **Q3 — H3.** The bound lives with the verdict it qualifies, in the final's
  donedata, not in a side register: the donedata is already the per-final SSOT the
  runner reads, so the run and the audit read one declaration. `ParamListenTime`
  becomes a tester IXIT (`IxitConfig`, `--expect ixit.param_listen_time_ms=`) with
  the specification's default of 10 s, the CLI measures the deciding window, and
  the donedata audit checks each window timer against its bound.
- **Q4 — migration.** Each `liveness` guard moves to `required_emission`: its
  test-body deadline final becomes `observed_quiescence`, its preamble deadlines
  stay `precondition_unmet`, and where a fixture can suppress the emission a `_neg`
  ships with it. The migration ledger (`tools/liveness_migration_pending.txt`)
  lists the guards still to move and may only shrink. Pilot, done: the §4.2.4.2
  ARP Request-reception cases ARP_20/26/36 (with `_neg` cases on the lwIP fixture's
  `kArpFaultIgnoreWellFormedRequest`, so they are `FAULT_INJECTION`) and
  `IPv4_TTL_05`, whose TTL=1 iteration was never on the wire before (two guards,
  `REGISTRY` until a fixture flavor drops low-TTL datagrams). Each window is
  `ParamListenTime` plus `<ParamToleranceTime>`, the slack the specification adds
  to every listen, so a window never measures short of its bound.

  First sweep, done: 89 of the 122 ledger cases moved. The §4.2.4.2
  Request-reception family shares one template (`arp_required_reply`), and
  ARP_16..19 and ARP_41 now carry `_neg` cases on the same fault flavor. The
  sweep added three rules, each with its own check:

  - **One event name per window.** SCXML does not cancel a delayed `<send>` when
    its state exits, so a timer armed in an earlier state with the same event name
    can close a later window early. The donedata audit refuses an
    `observed_quiescence` final reachable through a timer event that another state
    also arms (`STALE_TIMER`), and refuses it for a pass or an inert fail when the
    deciding state also arms that event itself.
  - **Measurement slack on H3.** The CLI measures the window as the dwell in the
    deciding state, which runs a few milliseconds short of the timer's delay
    because the entry is stamped after the send is armed. H3 allows 20 ms
    (`kWindowMeasurementSlackUs`, the run loop's idle quantum) so a window
    declared equal to its bound, such as a specification's "within 500 ms", is
    not refused on that alone. The audit still requires the declared delay to
    cover the bound in full.
  - **The premise of a test-body window is a stimulus.** A migrated deadline fails
    the DUT only if the tester actually put the question. Every shared helper
    whose failure leaves the test body unrun records an unperformed stimulus:
    `driveSeamListen`, `driveSeamRawPassiveAccept`, `acceptPreambleConnection`
    (the tester accept of an active OPEN whose handshake is the preamble) and
    `queryTcpSeqRange`. `driveSeamPassiveOpen` deliberately does not, because the
    DUT's missing SYN+ACK also lands there and `TCP_BASICS_01` grades it.

  Second sweep, done: the nine SOME/IP cases in which the tester gave the DUT less
  than `ParamListenTime`, or required an order the specification does not
  (`docs/tech-debt.md` TD-64). It added two more rules:

  - **Answers the specification does not order are awaited in any order.** A case
    owed several answers has one waiting state per set of answers still owed, each
    with its own window, so the answer still owed always has a full window after
    its request. A compound state with one timer does not do this: H3 measures the
    dwell from the previous transition, which a first answer resets.
  - **S is enforced at the send primitive.** Most cases ignore an emitter's
    return value, so a send that failed would have left a migrated deadline to fail
    the DUT for a question never put. Every send primitive (raw Ethernet, UDP,
    TCP connect and send, the SD and RPC builders' own sockets, the responders'
    setup) records its failure as an unperformed stimulus named after the emitter
    the case called (`reportTxFailed`, `stimulus/tx_observer.h`). Outcomes that are
    observations, such as a receive that timed out, are not recorded.

  - **An answer the DUT also sends unprompted is attributed, not assumed.** Where
    the emission graded as the answer to a stimulus is one the DUT may also send on
    its own schedule (`SOMEIP_ETS_097`: a reconnect SYN, also sent by a retry
    timer), the stimulus first observes the DUT unprompted and fixes an instant
    before which no unprompted emission is due (`IStimulusObserver::observeWithin`,
    a wait whose elapsed bound is an observation). Only an emission before that
    instant passes; one after it is `property_unobserved`. The hypothesis the
    instant rests on (a quiet window predicts a quiet window, or an observed
    period holds) is stated in the case beside S, H1, H2 and H3
    (`docs/tech-debt.md` TD-66).

  Four of the 24 then left (`SOMEIP_ETS_060`, `_118`, `_127`, `_171`): their
  "preamble-only" silence was the unicast OfferService the procedure grades.
  Four more left as their machines were redesigned: `TCP_BASICS_03` split its one
  window into a handshake preamble and the ACK-of-FIN body and migrated, and
  `TCP_CALL_RECEIVE_04`, `TCP_URGENT_PTR_04` and `UDP_FIELDS_05` now fail an
  answer that carries the wrong value (`incorrect_emission`, `observed_violation`)
  while no answer stays inconclusive. `TCP_PROBING_WINDOWS_04` and `_05` grade
  what RFC 1122 does bound: an abort while probes are acknowledged, and a probe
  sooner than the DUT's own retransmission timeout.

  The last 14 closed the ledger (`docs/tech-debt.md` TD-65). The link-local
  cases gave each waiting state its own window. The DHCP template takes its
  window as a parameter. The two "without crashing" MSS cases grade survival
  with an ICMP Echo probe. And `SOMEIP_ETS_130`, whose normative sources
  disagree on whether the DUT answers, became the first `optional_emission`
  guard (Section 6).

---

## 9. Authorities

- ISO/IEC 9646-1, *Conformance testing methodology and framework — General
  concepts* (verdict definitions: pass / fail / inconclusive).
- ETSI ES 201 873-1 (TTCN-3 core language): the `error` verdict as a test-system
  condition.
- W3C SCXML 1.0 §5.5 (`<donedata>`): the per-case verdict carrier.
- J. Tretmans, *Test generation with inputs, outputs and repetitive quiescence*,
  Software — Concepts and Tools 17(3), 1996; and *Model based testing with
  labelled transition systems*, in Formal Methods and Testing, LNCS 4949, 2008:
  the ioco relation, in which quiescence is an observable output.
- L. Brandán Briones and E. Brinksma, *A test generation framework for quiescent
  real-time systems*, FATES 2004, LNCS 3395, 2005: quiescence observed through a
  bounded timeout, valid when the bound covers the specification's.
