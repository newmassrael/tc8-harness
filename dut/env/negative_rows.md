# Negative rows — rationale

`docs/spec/inventory_overrides.json` carries the **values** of the negative-row
axis (`neg_wrong_token` / `neg_expect_fail` / `neg_expect_overrides`); this file
carries **why** each row exists — and, just as importantly, **why most cases have
none** — and is the home of their spec-section citations.

Same split, and for the same forced reason, as
[expect_overrides.md](expect_overrides.md): `mnemosyne.toml`'s `[workspace]`
records that `docs/spec/*` is immutable legacy outside Mnemosyne's managed
surface, so a `§` placed there would carry no binding. `dut/` is a scan root, so
the citations below stay bound. The JSON's own `*_ref` convention already
separates a value from its prose.

## What a negative row is

A conformance guard that can never fire is vacuous: it validates nothing while
looking like coverage. A **negative row** is a case's authored self-check against
that. It replaces ONE `--expect` value with a deliberately wrong one and asserts
the harness lands on a specific `fail:` verdict — proving the guard reacts to the
value rather than passing regardless.

This is one of four **dispositions** every registered positive case must carry
(`docs/verdict_policy.md` Section 6, debt D7), enforced exhaustively by
`tools/negative_coverage_audit.py` in CI and pre-commit:

| disposition | where it lives |
|---|---|
| `SOUND_ROW` | **this axis** — an expect-flip row |
| `FAULT_INJECTION` | a `<case>_neg` registered case driving a faulty DUT flavour |
| `REGISTRY` | `tools/conformant_absence_registry.json` |
| `DEFERRED` | `tools/deferred_negatives.json` |

A case in none of them is UNDISPOSED: its non-vacuity is unproven and untracked.
So the absences below are not gaps — each one is a case whose disposition is a
*different* one of the four, and the audit is what keeps that honest.

**The recurring reason a case has no row:** its guard asserts DUT BEHAVIOUR (must
emit a correct frame / must not emit a prohibited one / must emit at all) rather
than a comparison against an operator-supplied value. No `--expect` flip can
fault such a guard, so the row would be vacuous — those cases belong in the
registry instead.

## How a row is applied

`--negative-row` makes the harness build `base -> neg_wrong_token ->
neg_expect_overrides`. Appending is the whole mechanism: each `applyExpectToken`
assigns its field, so the later token simply wins — no merge logic, no precedence
table. The driver supplies only the base identity and asserts the verdict; it
never re-emits the flip.

`neg_expect_overrides` REPLACES the positive `expect_overrides` for the run: a
negative run's stimulus is the positive one, but its expectation baseline is
authored separately, and conflating them would let a positive override overwrite
the deliberate mistake.

Three load-time gates (`SpecInventory::load`) enforce what the bash tables could
only assert in prose:

1. half a row (`neg_wrong_token` xor `neg_expect_fail`) → reject;
2. `neg_expect_overrides` with no `neg_wrong_token` → reject: nothing would ever
   apply it. **38 of bash's 40 `NEG_CASE_EXPECT_OVERRIDES` rows were exactly this
   shape** — mirrored wholesale from the positive table onto cases that have no
   row to run — so they looked like negative coverage that did not exist. Only
   the 2 live ones (SOMEIPSRV_OPTIONS_11, SOMEIPSRV_SD_MESSAGE_13) migrated;
3. a `neg_expect_overrides` token sharing its key with `neg_wrong_token` →
   reject: applied last, it would overwrite the lie and the case would pass for
   the wrong reason. smoke-test.sh documented this as "none today" with nothing
   enforcing it; it is now enforced.

---

## SOMEIPSRV_FORMAT_14..18 — the SD entry identity fields

Cases: SOMEIPSRV_FORMAT_14, SOMEIPSRV_FORMAT_15, SOMEIPSRV_FORMAT_16,
SOMEIPSRV_FORMAT_17, SOMEIPSRV_FORMAT_18.

Each reads one `expected.*` SD-entry field, so flipping that field alone drives
the case onto its own mismatch final. The original five rows, and the reference
shape the rest follow.

## §5.1.5.5 SOMEIPSRV_OPTIONS_04 / _07 / _15 — endpoint values

Cases: SOMEIPSRV_OPTIONS_04, SOMEIPSRV_OPTIONS_07, SOMEIPSRV_OPTIONS_15.

They read `expected.*` endpoint values (`dut_iface_ip`, `udp_port`, `tcp_port`).

Cases SOMEIPSRV_OPTIONS_01, _02, _03, _05, _06 have **no row**: they verify spec
invariants on captured fields alone (length, type, reserved bytes, L4-Proto
presence), so an expectation flip cannot fault them.

## §5.1.5.5 SOMEIPSRV_OPTIONS_11 / §5.1.5.3 SOMEIPSRV_SD_MESSAGE_13 — Multicast Option

Both cases assert echoed/configured Multicast Option fields against `expected.*`
baselines. _11's `mcast_ipv4` flip lands directly on `fail_ipv4`;
SD_MESSAGE_13's `service_id` flip lands on `fail_ack_field` (the cond ANDs across
multiple echoed fields).

These are also **the only two cases carrying a `neg_expect_overrides`**
(`eventgroup_id=0x0008`, mirroring their positive `expect_overrides`) — their
stimulus subscribes to the multicast-configured eventgroup, so the negative run
needs the same baseline. Neither collides with its own flip key
(`mcast_ipv4` / `service_id` vs `eventgroup_id`), which gate 3 now enforces.

Cases SOMEIPSRV_OPTIONS_08, _09, _10, _12, _13, _14 have **no row**: they verify
spec invariants on captured fields alone (length / type / reserveds / l4-proto
presence / port literal) — same precedent as OPTIONS_01/02/03/05/06.

## §5.1.5.3 SOMEIPSRV_SD_MESSAGE_03 / _05 / _07 / _11 / _15

Cases: SOMEIPSRV_SD_MESSAGE_03, SOMEIPSRV_SD_MESSAGE_05, SOMEIPSRV_SD_MESSAGE_07,
SOMEIPSRV_SD_MESSAGE_11, SOMEIPSRV_SD_MESSAGE_15.

_03/_04 read `expected.major_version`, _05/_06 read `expected.minor_version`,
_07 reads `expected.ttl`, _11 reads `expected.service_id`, _15 reads
`expected.instance_id` / `eventgroup_id` / `major_version`.

Cases SOMEIPSRV_SD_MESSAGE_14, _16, _17, _18, _19 have **no row**: they verify
spec-defined sentinels (TTL=0 plus the literals 0xFFFE / 0x0002 / 2) on captured
fields alone — same precedent as OPTIONS_01/02/03/05/06.

## §5.1.5.3 SD_MESSAGE_02 + SOMEIPSRV_RPC_14 / _17 — why their rows were removed

Count/liveness cases whose sole fail is a precondition-break. The old
`service_id=0x0000` rows merely timed the gate out before the real observation —
vacuous, so they were removed rather than kept as false coverage. They are
liveness guards in `tools/conformant_absence_registry.json`, alongside the former
"omitted" captured-only cases (SOMEIPSRV_SD_MESSAGE_01, SOMEIPSRV_RPC_01, _02,
_13).

Expect-flippable cases with no verified sound row yet (SOMEIPSRV_SD_MESSAGE_04,
_06) are in `tools/deferred_negatives.json`. See `docs/verdict_policy.md`
Section 6.

## §5.1.6 SOMEIP_ETS sound expect-flip negatives

Cases: SOMEIP_ETS_005, SOMEIP_ETS_007, SOMEIP_ETS_008, SOMEIP_ETS_009,
SOMEIP_ETS_019, SOMEIP_ETS_022, SOMEIP_ETS_027, SOMEIP_ETS_028, SOMEIP_ETS_029,
SOMEIP_ETS_030, SOMEIP_ETS_031, SOMEIP_ETS_032, SOMEIP_ETS_034, SOMEIP_ETS_035,
SOMEIP_ETS_038, SOMEIP_ETS_039, SOMEIP_ETS_044, SOMEIP_ETS_046, SOMEIP_ETS_047,
SOMEIP_ETS_048, SOMEIP_ETS_053.

Each is a stateless echo whose conformant payload is the case-local
`applyExpectedDefaults` SSOT; the `payload=` (or `tcp_port=`) token flips it so a
conformant DUT's correct echo lands `fail_phase2_*_mismatch`
(`observed_violation`), proving the byte-equality guard non-vacuous.

The §5.1.6 dut-mutation and liveness guards (the former `service_id=0x0000`
precondition-break rows) are in `tools/conformant_absence_registry.json`
(`docs/verdict_policy.md` Section 6).

## §4.2.4.1 ARP_13 / _14 / _15 — the ARP identity fields

Cases: ARP_13, ARP_14, ARP_15.

Each reads one `expected.*` ARP identity field, so flipping it drives the case
onto its own mismatch final — the ARP analogue of FORMAT_14..18.

## §4.2.4.1 ARP_03..06 — Phase 2

Cases: ARP_03, ARP_04, ARP_05, ARP_06.

ARP_03/05: override `arp.tester_ip` so the learning stimulus injects a *wrong*
sender_proto_ip; the DUT's cache stays cold for the real tester IP; the
UT-provoked unicast egress (envelope pinned to the `ipv4.tester_ip` topology
identity, untouched by this override) then triggers a real ARP Request → the case
lands on `fail_unexpected_arp_request`.

ARP_04/06: override `arp.tester_mac` so the SCXML `expected.tester_mac`
mismatches the MAC actually injected (hardcoded in `arp_builder.h`); the observed
UDP's Eth-dst == injected synthetic MAC != expected → lands on
`fail_wrong_eth_dst`.

## §4.2.4.2 ARP_43 / _44 — Phase 3a field-check

Cases: ARP_43, ARP_44.

Opened via the Phase 3b CLI split (`dut.ip` / `dut.mac` feed the stimulus,
`arp.dut_iface_ip` / `arp.dut_iface_mac` feed the SCXML expectation). Overriding
only the iface key shifts the SCXML comparison target without silencing the DUT;
the SCXML fail guards were also relaxed (dropped the
`sender_hw == expected.dut_iface_mac` conjunction) so the override reaches the
intended fail branch instead of `fail_no_reply`.

## §4.2.4.2 ARP_32..35 — Phase 3b Group C cache-merge

Cases: ARP_32, ARP_33, ARP_34, ARP_35.

Override `arp.tester_mac2` so the SCXML expectation no longer matches the DUT's
observed UDP egress eth_dst (= real MAC2, still hardcoded to
`kTesterInjectedMac2` in `arp_builder.h`). The observed eth_dst equals neither
`expected.tester_mac` (MAC1 = 02:00:00:00:00:A1) nor the overridden
`expected.tester_mac2`, so the SCXML falls through to
`fail:udp_eth_dst_neither_mac1_nor_mac2`. This validates the pass-guard
dependency on `tester_mac2` without needing a DUT that actually does the wrong
thing.

## §4.2.4.2 ARP_39 / _40 — Phase 3c Group D stateful learning

Cases: ARP_39, ARP_40.

Override the MAC the SCXML compares the DUT's UDP egress eth_dst against. Without
`arp_ignore=8` (`run_negative_case` omits the per-case toggle to keep the runtime
path symmetric with other negatives), the DUT learns the tester KERNEL's MAC from
the auto-Reply race; that lladdr != the wrong overridden value, so the SCXML lands
on `fail:udp_eth_dst_not_injected_macN` — the intended fail branch. The test
asserts the dependency on the per-case MAC expectation, not on the cache
stickiness mechanism the positive path exercises.

## ARP_45 — two-Request target_hw check

Override `arp.tester_mac` so the SCXML expectation for the FIRST Reply's
target_hw no longer matches the DUT's actual reply (target_hw = real MAC1 from
the injected Request). Lands on the first-response fail branch.

## §4.2.4.2 ARP_48 / _49 — Phase 3c Group E timeout

Cases: ARP_48, ARP_49.

Override the MAC the SCXML expects on the FIRST DUT UDP egress. The cache-expiry
path itself does not matter for the negative — UDP1 fires while the cache still
has MAC1 (whether REACHABLE or DELAY), and the SCXML's `wait_udp1` fail branch
fires before the rest of the stimulus completes.

## ARP_46 / _47 — why they stay closed

Their guards check hardcoded RFC constants (`hw_type=1`, `hw_addr_len=6`) with no
`expected.*` override knob. Reaching those fail branches requires a
non-conformant DUT.

## §4.4 IPv4 — why most have no row

The §4.4 conformant-absence cases live in `tools/conformant_absence_registry.json`
(`docs/verdict_policy.md` Section 6): no `--expect` flip can fault them — each
guard asserts DUT behaviour, not a comparison against an operator value.

- **incorrect_emission** (DUT emits, value must be right): IPv4_HEADER_01 (Total
  Length >= RFC 791 min), IPv4_VERSION_03 (Version=4), IPv4_FRAGMENTS_05 (egress
  UDP MF/offset=0), IPv4_ADDRESSING_01 (UT received-count), IPv4_HEADER_05
  (§4.4.4.1, 576-byte Echo Reply payload).
- **liveness** (must emit an IPv4 packet, no wrong-value variant):
  IPv4_HEADER_03, IPv4_VERSION_01, IPv4_TTL_05.
- **prohibited_emission** (silence conformant, must not emit):
  IPv4_REASSEMBLY_06, IPv4_REASSEMBLY_07, IPv4_REASSEMBLY_09.

IPv4_TTL_01, IPv4_CHECKSUM_05 and IPv4_ADDRESSING_02 graduated to
FAULT_INJECTION — they now carry lwIP `_neg` self-validation cases, so they are
no longer conformant-absence registry rows.

## §4.3 ICMPv4 — why most have no row, and why TYPE_12 does

The §4.3 conformant-absence cases live in `tools/conformant_absence_registry.json`
(`docs/verdict_policy.md` Section 6): no `--expect` flip can fault them.

- **incorrect_emission**: ICMPv4_ERROR_02 (§4.3.3.1, Parameter Problem
  Pointer=22; Linux emits 20, RFC-792 latitude), ICMPv4_TYPE_11 (Timestamp Reply
  originate/receive/transmit), ICMPv4_TYPE_18 (Dest Unreachable code=2).
- **prohibited_emission**: ICMPv4_ERROR_03, ICMPv4_ERROR_04, ICMPv4_ERROR_05,
  ICMPv4_TYPE_04, ICMPv4_TYPE_05, ICMPv4_TYPE_10, ICMPv4_TYPE_16.
- **liveness**: ICMPv4_TYPE_22.

**ICMPv4_TYPE_12 keeps a sound row**: its `echo_id` is an operator-supplied
expected value, so flipping `icmpv4.echo_id` drives the SCXML into the
id-mismatch branch (higher specificity than the seq branch), proving the
identifier-echo conjunct is load-bearing. ICMPv4_TYPE_09 is the structural twin
but its row was unverified on the wire — deferred
(`tools/deferred_negatives.json`) until a smoke run confirms it lands on fail.

## §4.4.4.6 IPv4_FRAGMENTS_01

Flipping `icmpv4.echo_id` moves the pass conjunct (echo_id match) out of reach so
the SCXML lands on `fail_echo_id` (the explicit mismatch branch fires before
`fail_data_mismatch` since it has higher specificity). Proves the echo_id match
is load-bearing in the reassembly path — not just "any DUT reply".

## §4.4.4.6 IPv4_FRAGMENTS_02 / _03 / _04

Cases: IPv4_FRAGMENTS_02, IPv4_FRAGMENTS_03, IPv4_FRAGMENTS_04.

Flipping `icmpv4.echo_id` moves phase 2's pass conjunct out of reach — the DUT's
reassembled Echo Reply has the real `kIcmpEchoId` in its header, but the SCXML
compares against the wrong expected. Lands on `fail_echo_id` with the
case-specific reason string (the compound template's 3-way phase-2 fail split
mirrors FRAGMENTS_01's diagnostic granularity). Proves the phase 2 echo_id
conjunct is load-bearing across all three compound consumers.

## §4.4.4.7 IPv4_REASSEMBLY_04

Flipping `icmpv4.echo_id` moves the pass conjunct (echo_id match on the
unordered-reassembly Echo Reply) out of reach. The DUT still reassembles by
offset key and emits Echo Reply with the real `kIcmpEchoId`, but the SCXML
compares against the wrong expected → lands on `fail_echo_id` with the
unordered-reassembly reason string. Proves the echo_id match is load-bearing on
the out-of-order path — complements FRAGMENTS_01's same-axis check on the
in-order 2-fragment path.

## §4.4.4.7 IPv4_REASSEMBLY_12

Same axis as REASSEMBLY_04 — flipping `icmpv4.echo_id` sends the pass conjunct
out of reach so the SCXML lands on `fail_echo_id` with the low-TTL reason string.
Proves the echo_id match is load-bearing on the Low-TTL reassembly path.

## §4.4.4.7 IPv4_REASSEMBLY_10, and why _11 has no row

**IPv4_REASSEMBLY_10**: flipping `icmpv4.echo_id` sends phase_a's pass conjunct
out of reach. The DUT reassembles Phase A (inside `ipfrag_time=2` s) and emits
Echo Reply with the real id=0x1234, but the SCXML compares against 0xFFFE →
lands on `fail_phase_a_echo_id`. Phase B's hypothetical reply is unreachable
since phase_a's terminal final state already ended the case. Proves the phase_a
echo_id match is load-bearing on the within-timer reassembly path.

**IPv4_REASSEMBLY_11 carries no row**: the case's positive path already lands on
`fail_timeout` on Linux (`ipfrag_time=2` dut_ns toggle + 3 s inter-fragment wait
= bucket expired before frag 1, no Echo Reply). An echo_id flip would land on the
same `fail_timeout`, providing zero diagnostic variance. Same precedent as _13
(overlap drop): no flippable conjunct can be observed when no reply lands.

## §4.8 TCP — why none have a row

The §4.8 conformant-absence cases live in `tools/conformant_absence_registry.json`
(`docs/verdict_policy.md` Section 6): no `--expect` flip can fault them — each
guard asserts DUT behaviour (must emit a correct segment, must not emit a
prohibited one, or liveness), not a comparison against an operator value.

The negative coverage for §4.8.6.2 TCP_CHECKSUM_01, §4.8.6.3 TCP_UNACCEPTABLE_01
and §4.8.6.6 TCP_FLAGS_INVALID_01 (and the other §4.8 sub-areas) is that registry
guard, not a row here. The former `ipv4.dut_iface_ip` flip rows only suppressed L3
observation (absence/timeout) and proved nothing about the guards; the
spurious-filter rejection in `tools/negative_coverage_audit.py` codifies why they
were removed.

## §4.6 UDP — why most have no row

The §4.6 conformant-absence cases live in `tools/conformant_absence_registry.json`
(`docs/verdict_policy.md` Section 6): no `--expect` flip can fault them — each
guard asserts DUT behaviour, not a comparison against an operator value.

- **incorrect_emission**: UDP_FIELDS_01/02 (src/dst port), UDP_FIELDS_06/07
  (Length), UDP_FIELDS_12 (§4.6.5.4 UT received length), UDP_FIELDS_13/14
  (pseudo-header checksum), UDP_USER_INTERFACE_01/05/06 (UT port count / src /
  dst port), UDP_Padding_02 (no even-payload padding), UDP_INTRODUCTION_03
  (§4.6.5.6 ICMP type 3 code 3).
- **liveness** (must originate UDP, no wrong-value variant): UDP_FIELDS_04
  (per-host egress), UDP_FIELDS_05 (per-host UT receipt).

UDP_USER_INTERFACE_07 and _08 below keep sound rows (the alias-IP axis).

## §4.6.5.5 UDP_USER_INTERFACE_07 — strict-axis, source

The stimulus pins the src_ip override to the conformant DIface-0 alias
(`kDutAliasIp4Be` = 172.16.0.5) via a constant in `udp_pilot_common.h`, so
flipping `ipv4.dut_alias_ip` diverts ONLY the SCXML expectation. The DUT still
emits with src=alias, the harness expected diverges, and the cond lands on
`fail_wrong_src_ip_or_port` — proving the strict-axis cond literal is
load-bearing rather than vacuous on the passing path.

## §4.6.5.5 UDP_USER_INTERFACE_08 — strict-axis, destination

Same pattern as UI_07 but on the destination axis. The stimulus pins target_ip to
the AIface-0 alias (`kTesterAliasIp4Be` = 172.16.0.4); flipping
`ipv4.tester_alias_ip` makes the SCXML expect a different dst, forcing the cond to
land on `fail_wrong_dst_ip`.
