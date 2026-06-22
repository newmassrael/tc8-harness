# lwIP DUT fixture

Runs the [lwIP](https://savannah.nongnu.org/projects/lwip/) unix-port
stack on a host tap interface as a persistent `--topology external` DUT,
with an Upper Tester (UDP 30600) implemented on the lwIP socket API.
It additionally hosts the AUTOSAR Testability endpoint (UDP 30700,
`lwip_testability_server.cpp`) — the standard PRS_TPSP UTM channel,
mirroring the Linux tc8-dut's additive listener on the same stack. The
same endpoint is also built as a standalone binary, `tc8-lwip-utm` — the
lwIP analog of `dut/utm` (`tc8-utm`): the OEM-deployable AUTOSAR
Testability UTM with none of the fixture's conformance extras.
This is the project's second DUT platform after the Linux reference DUT
(`dut/dut_service/tc8-dut`), and the first strict-embedded-stack
consumer of the per-platform `inventory_overrides.json` mechanism.

The fixture exists for two reasons:

1. **Harness portability proof** — every verdict difference against the
   single-pc Linux baseline must be explainable from the DUT stack
   alone, not from harness assumptions about Linux.
2. **A second deviation ledger** — lwIP's RFC deviations differ from
   Linux's; comparing the two `platform_known_fail` sets shows which
   TC8 assertions discriminate between real-world stacks.

## Build

```sh
git clone --depth 1 https://github.com/lwip-tcpip/lwip.git /tmp/lwip
cmake -S dut/lwip_dut -B build-lwip-dut -DLWIP_DIR=/tmp/lwip \
      -DCMAKE_BUILD_TYPE=Release
cmake --build build-lwip-dut -j4
```

The lwIP core is compiled by this directory's CMakeLists against
`dut/lwip_dut/lwipopts.h`, so the stack configuration cannot drift from
what the binary links.

The build produces two binaries: `tc8-lwip-dut` (the conformance fixture
— stack + opcode UT + testability endpoint) and `tc8-lwip-utm` (the
standalone AUTOSAR Testability UTM — stack + testability endpoint only,
no opcode UT). They share the platform-agnostic protocol core
(`src/testability/protocol_server.cpp`), the lwIP `SocketBackend` adapter
(`lwip_socket_backend.cpp`) and the stack bring-up
(`lwip_stack_bringup.{h,cpp}`); only the entry point and the set of
bundled servers differ.

## Sweep result (2026-06-11, lwIP master 8e75a40a)

Initial coverage came from two sweeps: 116 UT-independent cases
(ARP / ICMPv4 / IPv4 core / UDP) and the 116-case TCP corpus opened by
the UT port (opcodes 0x03..0x0B + OpPing). A same-day follow-up ported
the UDP opcode family (0x01 OpGetReceivedUdp / 0x02 OpTriggerSendUdp /
0x14 OpCreateUdpReceivePorts) and opened 33 more cases — all 33 PASS
after two fixture-environment additions (tester alias + Host-2 ARP
answerability, see the conf) and one conformance rule in the data
listener (multicast deny, below). 2026-06-11 ported OpQueryTcpInfo
(0x13) onto the connection pcb's own fields, retiring the last
UT-opcode-blocked bucket: `TCP_RETRANSMISSION_TO_03/_04` join the
PASS set (x2 consecutive), `_08/_09` join the deviation set (below).

A 2026-06-11 PM follow-up retired the SOME/IP-responder-blocked bucket
entirely: the §4.2 egress-provocation stimulus is now the UT 0x02
OpTriggerSendUdp the spec text literally asks for (harness-side change,
`emitTriggerSendUdpBoot`), and the fixture's ut-ping preflight was
re-pointed at the tester alias so freshly respawned DUTs start with the
primary tester IP genuinely cold in their ARP table (see the fixture
notes below). 19 of the 24 ARP egress cases PASS — including
`ARP_33`-sibling `ARP_34` and Group D `ARP_39/_40`, which the Linux
reference known-fails — and 3 join the deviation set.

A second 2026-06-11 PM follow-up retired the last ARP gap: UT 0x17
OpConditionArpCache ages the stack's own table by virtual seconds
(driving `etharp_tmr()` under the core lock — the exact code path
wall-clock aging takes), so `ARP_48/_49`'s re-ARP-after-timeout
envelope no longer needs the netns sysctl compression only the Linux
reference DUT can offer. The fixture conf declares
`TOPOLOGY_UT_ARP_CACHE_TIMEOUT_S=300` (tracking the compile-time
`ARP_MAXAGE` this build inherits from the lwIP default); both cases
PASS with pcap-verified spec wire order (learn → UDP(MAC1) [→
UDP2(MAC1) at half timeout] → DUT broadcast ARP Request after the
full timeout). UT 0x16 OpQueryCapabilities accompanies it — the
bitmap answer is what lets a tester see this DUT's sparse opcode set
(0x01..0x0B + 0x13..0x17) precisely, where OpPing's contiguous
feature-level byte honestly reports only 0x0B.

| Bucket | Count | Notes |
|---|---|---|
| Meaningful PASS | 216 | 107 non-TCP + 109 TCP |
| lwIP stack deviation (`platform_known_fail`) | 16 | 9 non-TCP + 7 TCP, each verified against lwIP source and/or pcap (below) |

`dut/lwip_dut/inventory_overrides.json` is the machine-readable single
source of truth for the deviation set; this table is a dated report.

The 39 `IPv4_AUTOCONF_*` cases (29 positive + 10 `_NEG`) sit outside
the sweep scope entirely: the fixture builds with `LWIP_AUTOIP`
disabled (`lwipopts.h`) and no UT opcode drives autoconf. They are
ledgered `expected:false` in the overrides file so the sweep command
below emits exactly the 216-case regression list (the meaningful-PASS
set) and `--vs-spec`
reports them as honest gaps.

## Verified lwIP deviations

Each entry was confirmed against lwIP source or the wire, never
inferred from the verdict alone. Sweep pcaps are reproducible with
`--log-dir`.

Non-TCP:

- **`ICMPv4_TYPE_11/_12` — ICMP Timestamp not implemented.**
  `src/core/ipv4/icmp.c` counts `ICMP_TS` in MIB2 stats and falls
  through to "type not supported".
- **`ICMPv4_ERROR_02` — ICMP Parameter Problem never emitted.** Only
  dest-unreachable and time-exceeded generators exist. (The Linux DUT
  carries the same known-fail for pointer-semantics reasons.)
- **`IPv4_FRAGMENTS_04` — reassembly bucket match omits the protocol
  field.** `IP_ADDRESSES_AND_ID_MATCH` compares (src, dst, id); RFC 791
  §3.2 requires the (src, dst, protocol, id) quad.
- **`IPv4_REASSEMBLY_11` — static reassembly timer ignores TTL**
  (RFC 791 §3.2 `MAX(TLB, TTL)` not implemented; same deviation class
  as Linux).
- **`IPv4_REASSEMBLY_13` — overlap reassembly structurally
  unsupported.** Chain validation requires exact
  `prev->end == next->start` contiguity, so an overlapped bucket never
  completes regardless of `IP_REASS_CHECK_OVERLAP`.
- **`ARP_05/_06` — no entry creation from unsolicited gratuitous
  Responses.** `etharp_input` (`src/core/ipv4/etharp.c`) updates an
  EXISTING table entry from any incoming ARP frame but creates one only
  when the DUT is the target (`for_us`) — the literal RFC 826 reception
  algorithm. A gratuitous Response (`target_ip == sender_ip`, neither
  the DUT) therefore leaves a cold cache cold; the UT-provoked egress
  emits the DUT's own ARP Request and the cases land
  `fail:dut_arp_request_after_gratuitous_learning`. The Linux reference
  passes these only via per-case `arp_accept=1` conditioning — a
  TC8-beyond-RFC expectation, not an lwIP RFC deviation.
- **`ARP_33` — same `for_us`-only entry creation, double-injection
  form.** Both injections are gratuitous Responses, so no entry ever
  exists for the merge clause to act on
  (`fail:dut_arp_request_after_double_injection`). Distinct mechanism
  from the Linux reference's known-fail on the same case
  (`arp_is_garp()` target_hw-shape check + 1 s LOCKTIME). `ARP_34`
  passes here because its first injection is a Request addressed to
  the DUT (entry created), after which lwIP's update-on-any-ARP merge
  honours the second MAC with no locktime — one of the few cases that
  discriminates the two stacks in lwIP's favour (`ARP_34/_39/_40`).

TCP:

- **`TCP_BASICS_17` — simultaneous open not implemented.** A SYN
  arriving in SYN-SENT produces no SYN+ACK (RFC 793 p32).
- **`TCP_FLAGS_INVALID_06` — RST instead of discard** for an acceptable
  bare ACK in SYN-SENT (RFC 793 p66; Linux silently drops).
- **`TCP_FLAGS_INVALID_07` — no challenge ACK** for an OTW-SEQ SYN in
  SYN-RCVD (RFC 793 §3.9).
- **`TCP_URGENT_PTR_04` — urgent/OOB path not implemented** (RFC 793
  §3.7). The UT answers `OpReceiveTcpDataOob` with zero bytes by
  design, loudly logged.
- **`TCP_RETRANSMISSION_TO_05` — no exponential SYN-RTO backoff.** The
  case asserts the SYN-retransmission RTO grows (RFC 1122 §4.2.3.1 /
  RFC 6298 §5). lwIP excludes SYN_SENT from RTO doubling (`tcp.c`
  `tcp_slowtmr`: "unless we are trying to connect"), so the SYN RTO
  holds the fixed ~1 s seed (measured 1 s / 1 s / 1 s on the wire) and
  phase 1's doubled-RTO check fails deterministically. Same root cause
  as `_09`'s missing 2*MSL SYN-RTO plateau — a genuine deviation, not a
  harness window. (`_06`, which only asserts the RFC 6298 §2.1 ~1 s
  initial RTO, passes on lwIP and is no longer ledgered here.)
- **`TCP_RETRANSMISSION_TO_08` — no 2*MSL RTO ceiling.** The spec
  expects the data-retransmission RTO to plateau at 2*MSL (60 s).
  lwIP keeps doubling per retransmit (`tcp.c` `tcp_backoff` shift,
  capped at `<<7`) with no 2*MSL clamp and aborts the connection at
  `TCP_MAXRTX` 12; within the 35 s observation budget the RTO never
  repeats. Deterministic
  `fail:rto_below_2_msl_did_not_plateau_within_observation_budget`
  (x2 2026-06-11).
- **`TCP_RETRANSMISSION_TO_09` — SYN RTO never backs off, pcb aborts.**
  lwIP excludes SYN_SENT from RTO doubling (`tcp.c`: "unless we are
  trying to connect") — fixed 1 s SYN cadence — and frees the pcb at
  `TCP_SYNMAXRTX` 6 (~7 s in), at which point `OpQueryTcpInfo` answers
  `kStatusUnknownSocket`. Deterministic `fail:tcp_info_query_failed`
  (x2 2026-06-11). A 2*MSL SYN-RTO plateau is structurally
  unobservable on this stack.
- **Latent (passes today): `TCP_RETRANSMISSION_TO_03` Karn check.**
  lwIP resets `pcb->rto` to the smoothed `(sa>>3)+sv` on EVERY new
  ACK (`tcp_in.c` "Reset the retransmission time-out"), discarding
  the backed-off value Linux preserves across Karn-excluded ACKs
  (RFC 6298 §5.3's "until ... a valid RTT sample" reading). The
  phase-2 assertion (`rto_us >= 350 ms`) still passes because the
  RFC 6298 `LWIP_TCP_RTO_TIME` seed keeps the smoothed value near
  1 s for the case's 1-2 RTT samples. A faster-converging variance
  decay or a lower RTO seed would flip this case into the deviation
  set — re-measure on any lwipopts or pin change.

## Phase F fault-injection seams

The fixture carries three inert-until-armed fault seams that the Phase F `_NEG`
self-validation cases drive (via the Upper Tester `OpSetEgressFlavor` 0x18 /
`OpSetIngressFlavor` 0x19 / `OpSetAppFlavor` 0x1A; the flavor catalog SSOT is
`include/tc8/upper_tester_protocol.h`). lwIP itself is never patched: the first two
are netif-level glue (`lwip_egress_fault.cpp` wraps `linkoutput`,
`lwip_ingress_fault.cpp` wraps `input`); the third is a discard skip in the shared
data listener (`src/upper_tester/ut_server.cpp`), where an RFC 1122
destination-address discard the IP stack has already delivered to the socket lives —
a post-delivery application decision, below the netif glue's reach:

- **Egress field-fault** rewrites one header field of a DUT-emitted frame (ARP
  §4.2 fields; UDP §4.6.5.4 src/dst port, length, checksum; TCP §4.8 SYN,ACK ack,
  DATA checksum, closed-port RST seq, active-OPEN SYN MSS, data-elicited ACK ack_num;
  ICMPv4 §4.3 Echo Reply id/seq; IPv4 §4.4 header TTL / header checksum on the Echo
  Reply). Used where the
  conformant DUT *emits* a frame whose field a positive case checks. A field rewrite
  leaves the frame's checksum stale, which is immaterial: libtins delivers the frame
  and does not validate the IPv4 header checksum on parse, so the guard reads the
  mutated field. (The structural fields libtins *does* gate on — TCP data_offset,
  IPv4 IHL/version/total_length below the minimum — are not faultable this way; the
  dissector drops them before the guard runs.)
- **Ingress reaction-fault** makes the DUT exhibit a forbidden *reaction* to an
  inbound frame. Three reaction flavors today:
  - *§4.2.4.2 ARP prohibited emission* — synthesize the forbidden ARP Reply, or
    wrongly learn the dropped Response's address (reply / learn).
  - *§4.3 ICMPv4 prohibited emission* — synthesize the ICMP reply a conformant DUT
    must NOT send, addressed back to the trigger's sender with the DUT's own source
    identity: `kIcmpFaultSynthInfoReply` (Information Reply for an Info Request,
    TYPE_16), `kIcmpFaultSynthEchoReply` (Echo Reply for a bad-checksum Echo /
    TYPE_10 or an unknown-type ICMP / ERROR_05), `kIcmpFaultSynthParamProblem`
    (Parameter Problem for a fragmented / ERROR_03 or broadcast / ERROR_04 trigger).
    Like the ARP reply synthesis, the conformant DUT emits nothing — so the input
    hook builds the whole frame (Ethernet + IPv4 + 8-byte ICMP, both checksums via
    lwIP's own `inet_chksum`) rather than corrupting an egress field. The guard reads
    only the reply's type + source IP.
  - *§4.8 TCP behavioral prohibited emission* — `kTcpSynthRst` synthesizes a RST on the
    connection's 4-tuple when a pure ACK arrives in ESTABLISHED (`§4.8.6.18`
    ACKNOWLEDGEMENT_04, the DUT must stay silent). The RFC 793 §3.9 guards check only the
    4-tuple + RST flag — never seq/ack — so the synthesized segment needs no connection-
    state tracking: the inbound trigger's swapped addresses give the whole 4-tuple, and
    seq/ack stay 0. Armed per-phase (after ESTABLISHED) so the handshake is unaffected. This
    is the behavioural seam the egress field-fault cannot reach — there is no DUT-emitted RST
    to corrupt, so the hook synthesizes it. (The same seam generalises to the other §4.8
    must-not-respond guards — `dut_emitted_response_to_*` / `dut_acked_*` — as they land.)
  - *§4.6.5.4 UDP prohibited acceptance* — `kUdpFaultAcceptBadChecksum` zeroes the
    inbound UDP checksum so lwIP's `chksum != 0` gate skips and delivers a datagram
    it must drop.
- **App-layer reception-fault** makes the data listener skip a destination-address
  discard that RFC 1122 places at the *application* layer (`§4.4.4.5` directed
  broadcast via `kAppFaultAcceptDirectedBroadcast`; `§4.6.5.6` all-systems multicast
  via `kAppFaultAcceptMulticast`). lwIP delivers both to the INADDR_ANY data socket
  (directed broadcast with `IP_SOF_BROADCAST_RECV` off; multicast because `ip4_input`
  accepts every multicast destination with `LWIP_IGMP` off), so the drop is genuinely
  the listener's, not the IP stack's — the flavor skips it so the receive-counting app
  reports a receipt it must have dropped. Unlike the two netif seams this is not a
  frame mutation; the datagram already reached the socket, so the fault lives in the
  shared data listener (`UpperTesterServer::dataListenerLoop`), armed lwIP-only. The
  same seam also faults the §4.6.5.5 UDP User-Interface **report**: the datagram is
  received correctly, but the GetReceivedUdp / CreateUdpReceivePorts Confirmation
  surfaces a wrong field — `kAppFaultReportWrongSrcPort` (UI_03),
  `kAppFaultReportWrongSrcIp` (UI_04), `kAppFaultReportWrongPayload` (UI_02),
  `kAppFaultMiscountPorts` (UI_01). This is the only faithful site for those guards:
  the stack delivered the right metadata, so a wrong report is the receive operation's
  defect, and an ingress rewrite would make the DUT faithfully report the rewritten
  value (no fault). The conformant path reports correctly (the `_neg`'s fault-inert
  branch).

**Why UDP_FIELDS_09/10/15 + DATAGRAMLENGTH_01 share one acceptance flavor.** On
lwIP these all drop at the *same* gate — the UDP checksum. lwIP ignores the UDP
Length field for plain UDP (`src/core/udp.c` checks only `p->len < UDP_HLEN`), so
the Length mutants (09 Length=0, 10 Length>payload, DATAGRAMLENGTH_01
Length<payload) are rejected only because the Length field is checksum-covered,
and FIELDS_15 corrupts the checksum directly. One "skip checksum validation"
fault (`kUdpFaultAcceptBadChecksum`, which zeroes the inbound checksum) therefore
makes them all accepted — the honest representation of the lwIP drop mechanics
(one flavor per drop gate, mirroring the egress catalog's one-flavor-per-field).

**Why UDP_FIELDS_08 is not faithfully faultable here.** The sub-8-byte
truncation drops *earlier*, at lwIP's `p->len < UDP_HLEN` minimum-length gate,
before the checksum is ever read — so the checksum-skip flavor cannot reach it.
Making the DUT accept it would require fabricating UDP header bytes the tester
never sent (growing the pbuf, synthesizing length/checksum), i.e. feeding the
DUT a *different* frame than the wire carried — not a faithful mutation of "the
DUT accepted what arrived." It is left without a `_NEG` rather than carry a
contrived reconstruction (the same honest stance as the §4.2 ARP
kernel-emission cases that have no firmware builder to fault).

**The inverse property — UDP_FIELDS_03/16 prohibited rejection.** FIELDS_03 (src
port 0) and FIELDS_16 (checksum 0) are valid edge-case datagrams the DUT *must
accept*. Their faithful fault is the opposite of acceptance: `kUdpFaultRejectValid`
makes the input hook *swallow* the inbound data-listener frame (never forward it
to lwIP), so the receive-counting app reports no receipt — modelling a DUT that
wrongly drops a datagram it must deliver. The `_NEG` passes only when that
rejection is observed (`ut_received == 0`); a conformant DUT still accepts
(`ut_received == 1`, the fault-inert branch).

**§4.4.4.5 app-layer reception fault — ADDRESSING_02.** The directed-broadcast
discard is not an IP-stack drop: lwIP (like Linux) delivers a directed broadcast to
the INADDR_ANY data socket, and the data listener drops it on the RECVINFO-recovered
destination address (`ut_server.cpp` `dataListenerLoop`) — RFC 1122 §3.2.1.3 places
this at the application layer. `IPv4_ADDRESSING_02_NEG` arms
`kAppFaultAcceptDirectedBroadcast` so the listener skips that discard and counts the
datagram; the `_NEG` passes only when the receipt is observed (`ut_received == 1`), and
a conformant DUT still drops it (`ut_received == 0`, the fault-inert branch). A wire
mutation cannot do this faithfully: rewriting the destination from the directed
broadcast to a unicast (to dodge the listener's check) would change the very field
under test, so a conformant DUT would accept the rewritten frame too — the seam stays
at the layer where the real decision is.

**Still outside this seam.** FIELDS_04 (egress to two hosts), FIELDS_05 (UI
source-IP reporting), and FIELDS_12 (65507-byte reassembly) each need their own
mechanism (egress routing, UI field, reassembly) and are out of scope.
`INVALID_ADDRESSES_01/02` (multicast / broadcast *source* address) drop *inside*
lwIP's `ip4_input` ("packet source is not valid"), keyed on the very source-IP field
under test — the only way past is to rewrite the source (the faithfulness trap above),
so they have no faithful fixture seam (Linux drops them at the martian-source filter
for the same reason). (`INTRODUCTION_02`, multicast *destination*, is now wired through
the §4.6.5.6 app-layer seam above — a wire probe confirmed lwIP delivers the multicast
to the socket, so the listener's deny is the real drop.)

**§4.8 TCP egress field faults.** The egress seam extends to TCP, but TCP is
stateful so each flavor is segment-selective (the link-output hook sees every DUT
segment; corrupting all of them would break the handshake the observed segment
depends on). The wired cases are listed below by flavor (the authoritative case/file
count is the Phase F floor `tools/fault_injection_floor.txt` plus the per-push smoke
lane — not hand-maintained here; BASICS_04/05 carry one sibling per iteration, mapped
in `tools/fault_injection_coverage.json`):

- `TCP_SEQUENCE_01_NEG` / `_03_NEG` / `_04_NEG` (`kTcpFaultSynAckAckWrong` — flip the
  passive-open SYN,ACK ack_num, gated on the SYN,ACK; the tester completes the handshake
  from the uncorrupted seq so the segment is still captured. 03/04 are §4.8.6.17 siblings
  with tester ISN 0 / wrap-around 2^32-1).
- `TCP_CHECKSUM_03_NEG` (`kTcpFaultDataChecksumWrong` — XOR a DATA segment's
  checksum, gated on payload so the handshake stays valid).
- `TCP_BASICS_04_NEG` / `_NEG2` / `_NEG3` (`kTcpFaultRstSeqWrong` — XOR the closed-port
  RST's seq off zero, gated on the RST flag). The positive has three fail-finals
  (SYN/FIN/Data iterations); each sibling injects one iteration's stimulus to prove the
  corresponding fail-final reachable.
- `TCP_BASICS_05_NEG` / `_NEG2` (`kTcpFaultRstSeqWrong`, reused) — same RST-seq flavor,
  but the positive's RST SEQ echoes the incoming ACK (kTesterPilotAckPhase*), so each
  sibling injects the SYN,ACK / bare-ACK iteration to prove its fail-final.
- `TCP_FLAGS_INVALID_02_NEG` (`kTcpFaultRstSeqWrong`, reused) — flip the LISTEN-state
  RST's seq off the incoming SEG.ACK, gated on the RST flag (§4.8.6.6).
- `TCP_MSS_OPTIONS_11_NEG` (`kTcpFaultSynMssZero`) / `TCP_MSS_OPTIONS_12_NEG`
  (`kTcpFaultSynMssDefault`) — walk the active-OPEN SYN's TCP options to the kind=2
  MSS option and zero its value (11) or force it to the 536 default (12), gated on
  the pure SYN so the passive SYN,ACK is untouched.
- `TCP_HEADER_01_NEG` (`kTcpFaultDataChecksumWrong`, reused) — self-validates
  HEADER_01's *checksum* conjunct only; its data_offset conjunct is unreachable
  (below).
- `TCP_HEADER_02/05/06_NEG`, `TCP_ACKNOWLEDGEMENT_02/03_NEG`, `TCP_SEQUENCE_02_NEG`
  (`kTcpFaultPureAckNumWrong`) — flip a pure DUT ACK's ack_num. The flavor gates on a
  pure ACK; the caller's arm timing names *which* one: PER-PHASE after the handshake for
  a data-elicited ACK (HEADER_02/05/06 §4.8.6.16, ACKNOWLEDGEMENT_02/03 §4.8.6.18) via
  `emitEgressFlavorArmMidStream` + a `kEgressArmSettle` pre-injection wait so the arm
  lands first; or armed UP FRONT for the single ACK of a SYN-SENT open (SEQUENCE_02
  §4.8.6.17). The handshake third leg (also a pure ACK) is escaped by the arm timing,
  not the gate. HEADER 02/05/06 differ only in the injected segment's Reserved field
  (default / 0 / 0xF), which the ack_num fault is independent of.

**Why TCP_HEADER_01's data_offset conjunct is not self-validatable here.** libtins
(`build/libtins-4.0/src/tcp.cpp`) throws `malformed_packet` when
`data_offset*4 < sizeof(tcp_header)` (i.e. data_offset < 5), so a segment with a
sub-minimum data offset never produces a `TcpFrame` — the tester observes nothing
and the `_neg` would land on `inconclusive`, not `pass`. The same fact makes
HEADER_01's *positive* `data_offset < 5` fail branch unreachable through the
dissector: only its `!checksum_valid` half can ever fire. HEADER_01_NEG therefore
reuses the data-checksum flavor and carries `data_offset >= 5` as an always-true
shape conjunct.

The remaining §4.8 field guards are deferred for specific reasons, not coverage
laziness:

- **TCP_BASICS_01 (SYN,ACK flags).** Faultable in principle (clear the SYN bit),
  but its positive drives `driveSeamPassiveOpen` — a kernel `connect()` trigger.
  Corrupting the SYN,ACK makes the tester kernel RST, so the seam's `acceptTcp`
  never confirms; whether that returns cleanly (timeout) or blocks needs verifying
  before shipping. Also, clearing the SYN bit *de-selects* the segment (the positive
  has no fail-final — only pass on SYN+ACK), so the violation is unobservable rather
  than a clean pass/fail flip.
- **TCP_CHECKSUM_01 (must-ACK a correct-checksum segment).** Its data-ACK guard has
  only pass + inconclusive — no fail-final (absence is `inconclusive`, a liveness
  guard), so there is nothing a fault could make reachable; it stays terminal in the
  registry by policy, not a fault target. (HEADER_02/05/06 — the data-ACK ack_num
  cases — are now wired via per-phase arming, above. HEADER_07/08/09/11 and CHECKSUM_02
  are must-not-respond cases — wrong seam for the egress field-fault, but reachable via the
  ingress-synthesis seam, like ACKNOWLEDGEMENT_04 below.)
- **TCP_ACKNOWLEDGEMENT_04 (RST-after-pure-ACK)** — now wired via the **ingress-synthesis
  seam** (`kTcpSynthRst`, the §4.8 TCP entry in the ingress reaction-fault list above), not
  the egress field-fault cluster. Its fail-final fires when the DUT *emits a RST* after a
  pure ACK — a behavioural misbehaviour the conformant DUT never makes, so there is no egress
  frame to corrupt; the input hook synthesizes the RST instead. This was the pilot for the
  behavioural-emission seam, now joined by the §4.8.6.16 **must-not-challenge-ACK** cluster
  (`HEADER_07/08/09/11_NEG`, `kTcpSynthAck` — synthesize a pure ACK on a malformed (bad data
  offset / zero checksum) or multicast-destination segment the DUT must drop, gated on SYN|PSH;
  the synthesized source IP is the DUT's own netif address, so the multicast trigger still
  yields a DUT-sourced reply). The remaining must-not-respond family
  (`dut_emitted_response_to_*`, FLAGS_INVALID / FLAGS_PROCESSING) is reachable the same way and
  lands as those cases are built.

## lwipopts.h alignment (why each non-default option exists)

Every entry carries its rationale in `lwipopts.h`; the
behaviour-shaping ones:

- `IP_REASS_MAXAGE 2` — harness fixes `<ipIniReassembleTimeout>` at 3 s;
  lwIP buckets live `(MAXAGE, MAXAGE+1]` s. The lwIP default 15 s fails
  `IPv4_REASSEMBLY_10`; lowering it flips `_11` into the known-fail set
  (the static timer cannot satisfy both).
- `LWIP_TCP_RTO_TIME 1000` — RFC 6298 §2.1 initial RTO SHOULD be 1 s
  (lwIP default is 3 s). More conformant, not a test accommodation.
- `TCP_MSL 30000` — TIME-WAIT = 2*MSL = 60 s, the value Linux hardcodes
  and `TCP_BASICS_11/_12` probe after.
- `LWIP_TCP_TIMESTAMPS 1` — RFC 7323; makes tester-side TIME-WAIT
  reopening deterministic when multi-phase cases reuse port quads
  (seq-only comparison against a random ISN is a coin flip).
- `LWIP_HOOK_TCP_ISN` + contrib `tcp_isn` addon — RFC 6528 ISN
  randomisation, seeded from `getrandom` in `main`. lwIP's default ISN
  is a near-constant tick counter: a security non-conformance, and the
  predictability kept colliding with tester-side TIME-WAIT remnants.
- `ARP_QUEUEING 1` — the per-case respawn means the first UT exchange
  of every case runs on an empty ARP cache; the default single-packet
  pending queue dropped the UT response in favour of the SYN the same
  RPC triggered.
- `SO_REUSE 1`, `LWIP_SO_LINGER 1`, `LWIP_SO_RCVTIMEO/SNDTIMEO 1`,
  `MEMP_NUM_NETCONN 16` — UT server requirements (listener rebinds over
  TIME-WAIT, ABORT primitive, bounded receive/send, socket pool).
- `LWIP_RAW 1` — the Testability ICMP group's `ECHO_REQUEST` primitive
  emits through a raw pcb (`IP_PROTO_ICMP`); lwIP's socket layer has no
  unprivileged ICMP datagram socket. No raw receive callback is ever
  registered, so only the egress path is enabled and the core
  `icmp_input` echo-reply behaviour the ICMPv4 cases observe is
  untouched.
- Defaults that already conform and must not change:
  `LWIP_BROADCAST_PING=0`, `LWIP_MULTICAST_PING=0`,
  `IP_REASS_CHECK_OVERLAP=1`.

## Upper Tester implementation notes (`lwip_ut_server.cpp`)

- Opcode surface: `OpGetReceivedUdp`/`OpTriggerSendUdp` (0x01/0x02) +
  `OpOpenTcpSocket`..`OpReceiveTcpDataOob` (0x03..0x0B) +
  `OpQueryTcpInfo` (0x13) + `OpCreateUdpReceivePorts` (0x14) +
  `OpPing` (0x15). `OpPing` reports `max_opcode` 0x0B — the top of the
  contiguous 0x01..0x0B block; the one-byte capability field cannot
  express the sparse 0x13/0x14.
- `OpQueryTcpInfo` reads `state`/`rto`/`nrtx`/`unacked` off the
  connection pcb under the core lock (the same fd→pcb bridge the
  ABORT primitive uses) and translates to the wire's Linux TCP_INFO
  conventions: state renumbered (`tcpbase.h` order differs), `rto`
  ticks × `TCP_SLOW_INTERVAL` (500 ms) → microseconds, `unacked` =
  segment count on the unacked queue.
- The UDP data listener is a core-API `udp` pcb with a recv callback,
  not a socket thread: `ip_current_dest_addr()` inside the callback
  provides the original IP destination (the role IP_PKTINFO plays on
  Linux) without compiling in `LWIP_NETBUF_RECVINFO`.
- The data listener applies two application-layer conformance rules,
  both mirroring observables the Linux DUT gets elsewhere: directed-
  broadcast receipts are discarded (RFC 1122 §3.2.1.3, same app-layer
  rule as the Linux tc8-dut), and multicast receipts are denied
  (RFC 1122 §4.1.1 as inverted by TC8 §4.6.5.6 UDP_INTRODUCTION_02) —
  lwIP's `ip4_input` accepts every multicast destination when
  `LWIP_IGMP=0`, and compiling IGMP in would not help because
  `igmp_start` auto-joins 224.0.0.1 on netif-up.
- `OpTriggerSendUdp`'s src-IP override (§4.6.5.5 UI_07 caller-specified
  Source IP) maps to `udp_sendto_if_src()`: lwIP has no IPv4
  netif-alias to bind to; the core API emits from the caller-named
  source directly.
- `OpQueryTcpEstablished` answers from accept()/connect() completion
  (lwIP's socket layer exposes no TCP_INFO equivalent); the acceptor
  polls at 200 ms so the answer trails the wire by at most one tick.
- The spec ABORT primitive (`OpAbortTcpSocket`) calls `tcp_abort()` on
  the raw pcb under the core lock: lwIP's `SO_LINGER{on,0}` close only
  aborts when unsent/unacked data remains (`api_msg.c`), an empty queue
  always closes gracefully with FIN. This is the fixture's one
  dependency on a private lwIP header (`lwip/priv/sockets_priv.h`).
- Socket ids are monotonic from process start, exactly like the Linux
  tc8-dut — multi-phase cases rely on phase 2 getting sid 2. The
  per-case fresh-id expectation is satisfied by the fixture respawning
  the DUT per case (see below), never by resetting the counter.

## Testability endpoint notes (`lwip_socket_backend.cpp`)

The AUTOSAR Testability endpoint (PRS_TPSP §6, TC 1.2.0) runs the
platform-agnostic protocol core `tc8::testability::ProtocolServer`
(`src/testability/protocol_server.cpp`) — shared verbatim with the Linux
tc8-dut — paired with this directory's lwIP `SocketBackend` adapter
(`lwip_socket_backend.cpp`). The dispatch logic, wire codec
(`include/tc8/testability_protocol.h`) and ICMP Echo Request body builder
(`tc8::wire`, compiled in from `src/wire/`) are the same translation units
the Linux endpoint runs; only the socket adapter differs, and the bullets
below record where lwIP's stack forces that adapter to diverge. Each
binary's `main()` (`tc8_lwip_dut.cpp`, `lwip_utm_main.cpp`) owns its
`ProtocolServer` directly — exactly as the Linux `dut_main` / `utm_main` do,
with no façade translation unit. Served standard groups: GENERAL (0x00),
UDP (0x01), TCP (0x02), ICMP (0x03), ICMPv6 (0x04), IP (0x05), IPv6 (0x06) and
ETH (0x0B) — the same set the Linux endpoint serves.

- The `CLOSE_SOCKET` abort RSTs via `tcp_abort()` on the raw pcb (the
  `lwip/priv/sockets_priv.h` fd→pcb bridge, shared with the UT ABORT
  primitive): lwIP's `SO_LINGER{on,0}` close FINs an empty queue. The
  Linux server's netlink `SOCK_DESTROY` TIME-WAIT-residual path has no
  lwIP analog and is dropped — `tcp_abort` reaches CLOSED directly, so
  there is no residual and no connected-4-tuple to track.
- `ECHO_REQUEST` emits through a raw pcb under the core lock (see
  `LWIP_RAW` above); the Echo Request body is built by the shared
  `tc8::wire` builder, which checksums it, and the raw pcb leaves it
  untouched (`chksum_reqd` defaults to 0) — no double-checksum.
- The ICMPv6 `ECHO_REQUEST` (group 0x04) is routed by the shared core, but
  this fixture's `lwipopts.h` sets `LWIP_IPV6 0`, so the lwIP backend has no
  ip6 path and answers E_NOK — surfaced, not silently accepted, the same way
  the unsupported `CONFIGURE_SOCKET` options do. The Linux backend implements
  it fully (AF_INET6 / `IPPROTO_ICMPV6`).
- The ETH `INTERFACE_UP` / `INTERFACE_DOWN` (group 0x0B) toggle the named
  netif's administrative state via `netif_set_up()` / `netif_set_down()` under
  the core lock (`netif_find` resolves the name; an unknown one is E_IIF). A
  single-process stack has no privilege gate, so a resolved netif succeeds —
  unlike the Linux backend, whose `SIOCSIFFLAGS` needs CAP_NET_ADMIN.
- The IP `STATIC_ADDRESS` (group 0x05) assigns the address + CIDR netmask via
  `netif_set_addr()` under the core lock, keeping the existing gateway. IP
  `STATIC_ROUTE` answers E_NOK: base lwIP routes by netif (one gateway per
  interface) with no general per-subnet route table, so a faithful subnet route
  is not expressible — surfaced, not silently accepted (the unknown-interface
  case is still E_IIF). The Linux backend installs it via `SIOCADDRT`.
- The IPv6 `STATIC_ADDRESS` / `STATIC_ROUTE` (group 0x06) both answer E_NOK on
  this fixture: `lwipopts.h` sets `LWIP_IPV6 0`, so there is no ip6 address or
  route path — surfaced the same way the ICMPv6 echo is, with an unknown
  interface still E_IIF. The Linux backend assigns / routes via `SIOCSIFADDR` /
  `SIOCADDRT` with an `in6_ifreq` / `in6_rtmsg` on an AF_INET6 socket.
- `CONFIGURE_SOCKET` maps TTL/TOS/Nagle to `lwip_setsockopt`; the DF
  (`IP_MTU_DISCOVER`), IP timestamp-option (`IP_OPTIONS`) and MSS
  (`TCP_MAXSEG`) parameters have no lwIP socket option and answer E_NOK
  — surfaced, not silently accepted.
- Response and asynchronous Event egress on the shared listener socket
  are serialised by a send mutex: lwIP gives no cross-thread send
  ordering on one netconn, unlike the Linux kernel the original relies
  on. The async-SP worker lifetime (LISTEN_AND_ACCEPT / RECEIVE_AND_-
  FORWARD) is a strict subset of its socket's, exactly as in the Linux
  server.
- The OEM extension/override seam (`registerPrimitive`) lives in the
  shared core, so both lwIP binaries carry it. Neither registers a handler
  — they serve only the standard groups as conformance binaries — but
  because each `main()` owns its `ProtocolServer` directly, an OEM deploying
  `tc8-lwip-utm` calls `server.registerPrimitive(...)` before `start()` to
  add vendor groups (e.g. ARP capability, for which PRS_TPSP defines no
  service primitive) without forking the core, exactly as on the Linux
  `tc8-utm`.

The endpoint is additive — a bind failure is logged and the fixture
keeps serving the UT cases — so it is inert in the push-triggered lwIP
regression slice (no testability stimulus drives it there). Exercising
its dispatch paths needs testability cases in the external-fixture
sweep, which is future work.

## Topology notes (`topology.d/lwip-tap.conf` profile)

- **Per-case DUT respawn** (`topology_stop_dut`): case stimuli
  hardcode the socket ids a freshly spawned DUT hands out, and passing
  cases legitimately leave auxiliary sockets open. Respawning restores
  the per-case fresh-DUT semantics the Linux fixture gets from
  `TOPOLOGY_SUPPORTS_DUT_SPAWN=1`.
- **Drain-before-kill ordering** (`ss`-polled condition wait before
  the DUT pkill, baselined against the bring-up socket snapshot): the
  reaped harness's tester sockets complete their FIN exchanges against
  the still-live lwIP and reach CLOSED / reopenable TIME-WAIT. Killing
  the DUT first mints orphaned FIN-WAIT-1 sockets that freeze once the
  tap disappears and answer a later run's SYN on the same port quad
  with a stale challenge-ACK (observed as TCP_CLOSING_07 alternating
  pass/fail). `ss -K` is not a substitute — SOCK_DESTROY silently
  no-ops on the verification host.
- Stimulus-suppression iptables leaks from killed prior runs are
  handled by smoke-test.sh flushing the harness-owned `tc8-stimulus`
  chain at bring-up — no fixture-side rule knowledge.
- **Readiness probes must not warm the DUT's primary-tester ARP entry**
  (`ut-ping --source-ip $LWIP_TESTER_ALIAS_IP`): every probe's reply
  path makes the DUT ARP-resolve the probe's source address — and the
  host's own ARP request for the DUT IP teaches the DUT
  `<sender_ip, host MAC>` per RFC 826 target-is-us learning — and this
  fixture has no way to flush the lwIP ARP table afterwards (per-case
  neigh conditioning is a Linux-netns affordance). Probing from the
  primary tester IP broke the §4.2 cold-cache cases two ways: the
  bring-up probe in `topology_preflight` warms the position-1 DUT, and
  the per-respawn poll in `topology_stop_dut` warms every later case —
  so both source from the tester alias. The warm entry now lands on an
  address (`<172.16.0.4>`) no §4.2 assertion references. (The
  testability readiness probe has no source-IP; a UTM run drives no
  §4.2 cold-cache case.)

## ARP egress provocation (SOME/IP-blocked bucket, RETIRED 2026-06-11)

ARP egress cases historically provoked the DUT-originated unicast UDP
datagram with a SOME/IP SubscribeEventgroup, expecting the Nack reply
that the vsomeip reference DUT produces — inert on this fixture (no
SOME/IP application), which parked all 24 cases `expected:false`. The
TC8 spec text for every one of those cases actually reads "DUT
CONFIGURE: Configure DUT to send a UDP Message from <DIface-0>
(src=<DIface-0-IP>, dst=<HOST-1-IP>)", and the harness now renders
that literally as a UT 0x02 OpTriggerSendUdp boot emit
(`emitTriggerSendUdpBoot`); the SD subscribe was a historical
substitute that predated the UT UDP opcodes. With opcode 0x02 already
ported here, the bucket opened wholesale: 19/24 PASS, `ARP_05/_06/_33`
joined the deviation ledger (gratuitous-learning, above), and
`ARP_48/_49` followed the same day once UT 0x17 OpConditionArpCache
landed (virtual-time table aging, above).

## Running the sweep

```sh
sudo -n dut/env/smoke-test.sh \
  --topology lwip-tap \
  $(dut/lwip_dut/sweep-cases.sh)
```

`sweep-cases.sh` is the single source of the case selection (overrides
ledger + category filter — its header documents both); CI exposes the
same command as an on-demand dispatch (single invocation,
JUnit-reported) via `.github/workflows/lwip-sweep.yml` against the lwIP
commit pinned in `dut/lwip_dut/LWIP_PIN`; the per-push smoke-test
workflow covers a 14-case regression slice. Dispatch the full sweep
when there is new evidence to gather — a pin bump (mandatory: re-run
and refresh `inventory_overrides.json` in the same commit), a session
touching the fixture or shared harness paths, or a refresh of the
dated table above.
