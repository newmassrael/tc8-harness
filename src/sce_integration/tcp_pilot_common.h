#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <optional>
#include <pcap/pcap.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "tc8/captured_event.h"
#include "tc8/upper_tester_protocol.h"
#include "sce_integration/tcp_captured.h"
#include "sce_integration/test_config.h"
#include "stimulus/ipv4_frame_builder.h"
#include "stimulus/tcp_segment_builder.h"
#include "stimulus/upper_tester_client.h"

namespace tc8::sce::tcp {

// §4.8.6.1 TCP_BASICS pilot. Consumers land on a thin helper surface so
// the per-case traits collapse to a spec-specific 4-line stimulus body
// and a one-line dispatch.
//
// The §4.8 pilot has two stimulus shapes — see emitTcpStimulus
// (raw-inject) vs connectToDutTcp (kernel-connect). The three port
// constants below split cleanly between them; keeping the dichotomy
// explicit prevents a future case from accidentally mixing a raw-
// inject port with a kernel-connect call site (or vice versa).

// **kernel-connect path** (BASICS_01/02/03). The Upper Tester opens a
// passive listener on this DUT-side port (OpOpenTcpSocket); the tester
// then issues a normal `connect()` from its netns and the kernel
// completes the 3-way handshake end-to-end. SCXML observes the DUT-
// emitted SYN,ACK / plain ACK that fall out of the handshake. Value
// chosen above vsomeip's range (30490..30510) and the UT RPC port
// (30600) so a packet-trace reader can identify the §4.8 pilot
// listener at a glance.
inline constexpr std::uint16_t kBasicsListenPort = 12345U;

// **raw-inject path** (BASICS_04/05). A deliberately-unbound DUT port
// the tester targets with a hand-built TCP segment (emitTcpStimulus).
// No DUT-side listener exists, so Linux's `tcp_v4_rcv` falls into
// `tcp_v4_send_reset` and emits the RFC 793 §3.9 p65 prescribed RST
// response. Value chosen well clear of kBasicsListenPort so a stray
// crossover (e.g. a future case wiring the wrong port into the wrong
// helper) fails loudly on the wire rather than silently colliding.
inline constexpr std::uint16_t kBasicsClosedPort = 54321U;

// **raw-inject path source** (BASICS_04/05 only). Tester-side source
// port emitTcpStimulus pins on every hand-built segment. The kernel-
// connect path uses ephemeral source ports the kernel chooses, so this
// constant is irrelevant to BASICS_01/02/03. 49152 is the start of the
// IANA dynamic/private range (RFC 6335) — clear of vsomeip's range and
// of the UT RPC tester source port (ut::kTesterSrcPort, 20100), so
// captures show "src=49152" → §4.8 raw-inject and "src=20100" → UT channel
// without further inspection.
inline constexpr std::uint16_t kBasicsTesterPort = 49152U;

// **active-open path** (BASICS_06+). The DUT issues OpOpenTcpSocket
// (Active) and connect()s to <tester_ip>:kBasicsActiveRemotePort; this
// port is where the tester's listening socket (or absence thereof for
// pure SYN-observation cases) lives. Distinct from kBasicsListenPort —
// they are *opposite* ends of the connection, mixing them in either
// direction would have the tester probe its own DUT-bound listener.
inline constexpr std::uint16_t kBasicsActiveRemotePort = 23456U;

// **active-open path** local DUT port. tc8-dut binds (iface_ip,
// kBasicsActiveLocalPort) before connect() so the DUT-side source
// endpoint is deterministic for tester filtering. Chosen above the
// passive listen port and outside the raw-inject pair so each path's
// port quad is visually distinct in pcap. Kept fixed across cases — a
// per-case override would buy nothing because the active fd's lifetime
// is bounded by OpCloseTcpSocket within the same case.
inline constexpr std::uint16_t kBasicsActiveLocalPort = 49500U;

// Listen backlog for the tester's auxiliary listener. backlog=1 covers
// the BASICS_06+ pattern of one DUT connect per case; a larger backlog
// would only invite a stale handshake from a previous case on the same
// worker to confuse the next. Same rationale as
// `openTcpPassive(... listen(fd, 1) ...)` in upper_tester_server.cpp.
inline constexpr int kBasicsTesterListenBacklog = 1;

// Initial stimulus wait. Short by UDP-UT standards because the
// raw-inject path is kernel-level (no application bind involved) and
// the kernel-connect path explicitly synchronises through the UT
// Confirmation before emitting the TCP segment. 200 ms gives pcap
// headroom to open and the tester netns arp-neigh path to be ready
// without burning smoke-test wall time. UT-channel boot wait
// (kTcpUtBootWait, 1500 ms) is a separate constant — see the
// kernel-connect helpers below.
inline constexpr auto kTcpPilotInitialWait = std::chrono::milliseconds(200);

// Inter-phase gap for compound raw-inject stimuli (BASICS_04 with 3
// iterations SYN/FIN/Data, BASICS_05 with 2 iterations SYN+ACK/ACK).
// Each iteration is one TCP segment that provokes one DUT RST; pcap
// captures all phases sequentially and the SCXML walks listening_phaseK
// states one tcp_observed at a time. 200 ms is large enough that
// successive RSTs sit in pcap as distinct events without merging via
// scheduler jitter, and small enough that the total stimulus wall-time
// stays well under the per-case CASE_TIMEOUT_SEC budget.
inline constexpr auto kTcpPilotPhaseGap = std::chrono::milliseconds(200);

// RFC 1122 §4.2.3.2 caps a delayed ACK at < 500 ms ("the delay MUST be
// less than 0.5 seconds"). A DUT honouring delayed-ACK (e.g. the lwIP
// fixture, which drains its TF_ACK_DELAY queue from the ~250 ms fast
// timer) legally coalesces the acknowledgements for back-to-back
// segments into a single cumulative ACK, and abandons a still-pending
// ACK when the application closes over unread RX data (RST-on-close).
// Tests that assert a per-segment ACK cadence — or that must observe a
// data ACK before teardown — space the tester's segments and the
// follow-up close past this ceiling: with the gap above 500 ms every
// conformant stack emits one cumulative ACK per segment before the next
// stimulus arrives, so the strict per-segment matchers hold for both
// quickack-style (Linux) and delayed-ACK (lwIP) DUTs without loosening
// the matcher. 600 ms = 500 ms RFC ceiling + scheduler-jitter margin.
inline constexpr auto kDelayedAckSettle = std::chrono::milliseconds(600);

// Seed SEQ value the tester uses on its SYN / flag-stimulus segments.
// Chosen non-zero so BASICS_04's pass criterion ("DUT's RST SEQ == 0")
// is structurally distinct from the tester's SEQ — a bug where the
// pipeline mirrors the stimulus seq back into Captured would false-fail
// the SEQ-zero guard rather than silently masquerade as pass.
inline constexpr std::uint32_t kTesterInitialSeq = 0x10203040U;

// Forward offset used to construct an out-of-window SEQ for an
// established connection's receive window. Linux's max plausible
// window scale is 2^14 × 64 KB ≈ 1 GB; a 16 MB offset above the
// kernel's snd_nxt is comfortably outside that ceiling without
// risking 32-bit SEQ wraparound on a fresh connection. Used by
// §4.8.6.3 UNACCEPTABLE_04 / _06 / _14 to drive the DUT's
// RFC 793 §3.9 p70 challenge-ACK path.
inline constexpr std::uint32_t kOutOfWindowSeqOffset = 0x1000000U;

// Forward offset used to construct an unacceptable ACK number — one
// that acknowledges bytes the DUT has not (and will never have) sent
// for the embryonic / fresh connection. 256 MB above the captured
// ISN_d puts the ACK well past any plausible in-flight window. Used
// by §4.8.6.3 UNACCEPTABLE_03 / _08 to drive the DUT's RFC 793
// RFC 793 §3.4 unacceptable-ACK RST path.
inline constexpr std::uint32_t kUnacceptableAckOffset = 0x10000000U;

// §4.8.6.9 TCP_MSS_OPTIONS raw-passive-handshake reservation block.
// One DUT-side listen port + one tester source port per case so a
// case's TIME-WAIT residue (Linux's hardcoded 60 s timer) on a worker
// netns does not collide with the next case's bind. Listen base 13000
// is well clear of kBasicsListenPort (12345) and kBasicsClosedPort
// (54321); tester source base kBasicsTesterPort + 50 is two slots
// above any current §4.8 raw-inject usage. The constants are named
// per-case rather than `+ N` arithmetic in the SCXML guard so the
// generated cond string stays readable in the .inl dump.
inline constexpr std::uint16_t kTcpMssOptionsListenPort02     = 13002U;
inline constexpr std::uint16_t kTcpMssOptionsTesterSrcPort02  = kBasicsTesterPort + 52U;
inline constexpr std::uint16_t kTcpMssOptionsListenPort03     = 13003U;
inline constexpr std::uint16_t kTcpMssOptionsTesterSrcPort03  = kBasicsTesterPort + 53U;
inline constexpr std::uint16_t kTcpMssOptionsListenPort01a    = 13011U;
inline constexpr std::uint16_t kTcpMssOptionsTesterSrcPort01a = kBasicsTesterPort + 61U;
inline constexpr std::uint16_t kTcpMssOptionsListenPort01b    = 13012U;
inline constexpr std::uint16_t kTcpMssOptionsTesterSrcPort01b = kBasicsTesterPort + 62U;
inline constexpr std::uint16_t kTcpMssOptionsListenPort01v    = 13013U;
inline constexpr std::uint16_t kTcpMssOptionsTesterSrcPort01v = kBasicsTesterPort + 63U;

// §4.8.6.9 MSS_OPTIONS_05 (active, 2 iter) port-quad offsets. Each
// iter drives DUT to SYN-SENT on its own (local, remote) pair so the
// kernel-side TIME-WAIT residue from iter 1 (DUT-side LAST-ACK after
// UT close) does not collide with iter 2's bind on the same worker.
inline constexpr std::uint16_t kTcpMssOptions05Phase1LocalOffset  = 100U;
inline constexpr std::uint16_t kTcpMssOptions05Phase2LocalOffset  = 101U;

// MSS_OPTIONS_09 (active, 2 iter) port-quad offsets — same rationale.
inline constexpr std::uint16_t kTcpMssOptions09Phase1LocalOffset  = 110U;
inline constexpr std::uint16_t kTcpMssOptions09Phase2LocalOffset  = 111U;

// §4.8.6.1 BASICS_17 simultaneous-OPEN port-quad offset. Single
// 4-tuple (DUT_local = tester_remote_port + offset, etc.) — RFC 793
// RFC 793 §3.4 simultaneous-OPEN matches when both ends bind the same
// (src_ip, src_port, dst_ip, dst_port) inverted pair, which is
// what the helper's local_port + remote_port translation produces.
inline constexpr std::uint16_t kTcpBasics17LocalOffset            = 120U;

// MSS_OPTIONS_06 (passive, 2 iter) listen ports + tester source.
// Phase 1 = Mv smaller than DUT MSS; Phase 2 = Mv larger. Each iter
// runs its own raw-passive handshake on a distinct 4-tuple so a
// TIME-WAIT residue from phase 1 does not collide with phase 2's
// bind on the same worker netns.
inline constexpr std::uint16_t kTcpMssOptionsListenPort06a    = 13021U;
inline constexpr std::uint16_t kTcpMssOptionsTesterSrcPort06a = kBasicsTesterPort + 71U;
inline constexpr std::uint16_t kTcpMssOptionsListenPort06b    = 13022U;
inline constexpr std::uint16_t kTcpMssOptionsTesterSrcPort06b = kBasicsTesterPort + 72U;
// MSS_OPTIONS_10 (passive, single iter) — DUT defaults send MSS to
// 536 when the tester SYN carries no MSS option.
inline constexpr std::uint16_t kTcpMssOptionsListenPort10     = 13020U;
inline constexpr std::uint16_t kTcpMssOptionsTesterSrcPort10  = kBasicsTesterPort + 70U;

// §4.8.6.18 ACKNOWLEDGEMENT_03 (passive, single iter) — DUT replies to
// an in-window data segment with a pure ACK whose ack_num covers the
// payload. Listen 13030 / tester +80, well clear of the MSS_OPTIONS
// passive block (13002..13022) and the active-OPEN +120 block.
inline constexpr std::uint16_t kTcpAck03ListenPort            = 13030U;
inline constexpr std::uint16_t kTcpAck03TesterSrcPort         = kBasicsTesterPort + 80U;

// §4.8.6.18 ACKNOWLEDGEMENT_02/04 + §4.8.6.13 NAGLE_02/03 active-OPEN
// port-quad offsets (kBasicsActiveLocalPort/+N, kBasicsActiveRemotePort
// /+N). +130..+133 reserved block; rationale matches the §4.8 active-
// OPEN cluster reservation map (post-+120 BASICS_17).
inline constexpr std::uint16_t kTcpAck02LocalOffset           = 130U;
inline constexpr std::uint16_t kTcpAck04LocalOffset           = 131U;
inline constexpr std::uint16_t kTcpNagle02LocalOffset         = 132U;
inline constexpr std::uint16_t kTcpNagle03LocalOffset         = 133U;

// §4.8.6.19 CONTROL_FLAGS_05 + §4.8.6.14 URGENT_PTR_04 active-OPEN
// port-quad offsets. +140 / +142 reserved slots continue the
// active-OPEN cluster reservation map (post-+133 NAGLE_03).
// CONTROL_FLAGS_08 lives on a passive listener
// (kTcpControlFlags08ListenPort below) so it does not consume an
// active-OPEN slot.
inline constexpr std::uint16_t kTcpControlFlags05LocalOffset  = 140U;
inline constexpr std::uint16_t kTcpUrgentPtr04LocalOffset     = 142U;

// §4.8.6.10 OUT_OF_ORDER_03 active-OPEN port-quad offset. +143 reserved
// slot continues the active-OPEN cluster reservation map (post-+142
// URGENT_PTR_04). The case raw-injects four data segments — one
// in-order, two leaving a SEQ gap, and the gap-filler — and asserts
// the DUT's cumulative ACK does not advance past the gap until the
// fill segment arrives, then jumps to cover all queued data.
inline constexpr std::uint16_t kTcpOutOfOrder03LocalOffset    = 143U;

// §4.8.6.7 FLAGS_PROCESSING_10 active-OPEN port-quad offset. +144 reserved
// slot continues the active-OPEN cluster reservation map (post-+143
// OUT_OF_ORDER_03). The case asserts RFC 793 §3.9 piggyback semantics:
// with the 1st DUT data segment held unacked (TesterAutoAckDrop) and a
// small 2nd SEND queued by Nagle, a tester-injected piggyback (ACK +
// payload) must trigger a single DUT segment that carries both the
// queued payload AND the cumulative ack covering the tester payload —
// all within 0.5 sec.
inline constexpr std::uint16_t kTcpFlagsProcessing10LocalOffset = 144U;

// §4.8.6.10 OUT_OF_ORDER_01 active-OPEN port-quad offset. +145
// reserved slot continues the active-OPEN cluster reservation map
// (post-+144 FLAGS_PROCESSING_10). The case raw-injects one
// MSS-sized PSH+ACK and asserts the DUT's quickack-mode pure ACK
// covering the segment lands within the spec's 0.5 sec ceiling
// (RFC 1122 §4.2.3.2 MUST).
inline constexpr std::uint16_t kTcpOutOfOrder01LocalOffset    = 145U;

// §4.8.6.10 OUT_OF_ORDER_02 active-OPEN port-quad offset. +146
// reserved slot continues the active-OPEN cluster reservation map
// (post-+145 OUT_OF_ORDER_01). The case raw-injects two
// consecutive 100 B PSH+ACKs and asserts the DUT's cumulative ACK
// covering both lands within 500 ms — relaxed cumulative-ACK
// reading (vs. spec literal "single ACK") tolerates Linux's
// quickack-mode intermediate seg0 ACK (RFC 1122 §4.2.3.2 MUST).
inline constexpr std::uint16_t kTcpOutOfOrder02LocalOffset    = 146U;

// §4.8.6.10 OUT_OF_ORDER_05 active-OPEN port-quad offset. +147
// reserved slot continues the active-OPEN cluster reservation map
// (post-+146 OUT_OF_ORDER_02). The case raw-injects N=10
// MSS-sized PSH+ACKs at 5 ms inter-segment pacing and asserts the
// DUT emits at least N/2 = 5 pure ACKs — the RFC 1122 §4.2.3.2
// "every other segment" stretchACK floor (SHOULD).
inline constexpr std::uint16_t kTcpOutOfOrder05LocalOffset    = 147U;

// §4.8.6.12 PROBING_WINDOWS_02 active-OPEN port-quad offset. +148
// reserved slot continues the active-OPEN cluster reservation map
// (post-+147 OUT_OF_ORDER_05). The case raw-injects 1 B PSH+ACK
// with `window=0x8000` (MSB set) post-handshake to drive Linux's
// tcp_ack_update_window with an unsigned-MSB advertised window,
// then UT OpSendTcpData asserts the DUT honours the window as
// unsigned 32768 by emitting a data segment (RFC 1122 §4.2.2.3
// MUST — RFC 793 §3.1).
inline constexpr std::uint16_t kTcpProbingWindows02LocalOffset = 148U;

// §4.8.6.12 PROBING_WINDOWS_03 active-OPEN port-quad offset. +149
// reserved slot continues the active-OPEN cluster reservation map
// (post-+148 PROBING_WINDOWS_02). The case drives 3 sequential
// MSS-fill SENDs, raw-injects a window=0 ACK acknowledging only the
// 2nd of those segments (so seg3 remains outstanding under
// snd_wnd=0 → useable window negative), and asserts the DUT does
// not transmit any data segment past seg3's range (RFC 1122
// §4.2.2.16 MUST — RFC 793 §3.7).
inline constexpr std::uint16_t kTcpProbingWindows03LocalOffset = 149U;

// §4.8.6.12 PROBING_WINDOWS_05 active-OPEN port-quad offset. +150
// reserved slot continues the active-OPEN cluster reservation map
// (post-+149 PROBING_WINDOWS_03). The case raw-injects a window=0
// ACK after the DUT's first data segment, then queues a second SEND
// to keep Linux in persist mode and assert the DUT emits a zero-
// window probe (0-byte ACK at seq=snd_una-1) within Linux's first
// persist RTO (RFC 1122 §4.2.2.17 SHOULD — RFC 793 §3.7).
inline constexpr std::uint16_t kTcpProbingWindows05LocalOffset = 150U;

// §4.8.6.12 PROBING_WINDOWS_04 active-OPEN port-quad offset. +151
// reserved slot continues the active-OPEN cluster reservation map
// (post-+150 PROBING_WINDOWS_05). The case drives the persist-mode
// probe loop (small SEND + window=0 ACK + second SEND queued) and
// observes 3 successive zero-window probes at exponentially-doubled
// intervals, ACKing each with window=0 via state-entry-driven
// stimulus injection (RFC 1122 §4.2.2.17 MUST — RFC 793 §3.7).
inline constexpr std::uint16_t kTcpProbingWindows04LocalOffset = 151U;

// §4.8.6.12 PROBING_WINDOWS_06 active-OPEN port-quad offset. +152
// reserved slot continues the active-OPEN cluster reservation map
// (post-+151 PROBING_WINDOWS_04). The case observes 3 successive
// zero-window probes WITHOUT acking — Linux's `icsk_backoff`
// increments on each probe-fire so the inter-probe interval doubles
// naturally (RFC 1122 §4.2.2.17 SHOULD — RFC 793 §3.7).
inline constexpr std::uint16_t kTcpProbingWindows06LocalOffset = 152U;

// §4.8.6.11 RETRANSMISSION_TO_06 active-OPEN port-quad offset. +153
// reserved slot continues the active-OPEN cluster reservation map
// (post-+152 PROBING_WINDOWS_06). The case drives the DUT to issue
// an active OPEN against a tester endpoint that is not listening,
// suppresses the tester-kernel auto-RST via `TesterAutoRstDrop` so
// the DUT's SYN goes unanswered, and observes the SYN retransmit
// landing within the RFC 6298 §2.1 initial-RTO window (~1 s on
// Linux 6.5; SCXML guard bounds [800 ms, 1500 ms] via
// `frame_delta_us()`).
inline constexpr std::uint16_t kTcpRetransmissionTo06LocalOffset = 153U;

// §4.8.6.11 RETRANSMISSION_TO_04 active-OPEN port-quad offset. +154
// reserved slot continues the active-OPEN cluster reservation map
// (post-+153 RETRANSMISSION_TO_06). The case drives the DUT to
// ESTABLISHED + small SEND with `TesterAutoAckDrop` suppressing the
// tester-kernel auto-ACK so the DUT's data segment goes unACKed and
// the persist-mode RTO loop fires; SCXML guards observe 3 successive
// retransmits with monotonically-increasing per-state delta lower
// bounds tuned to Linux's TCP_RTO_MIN=200 ms baseline (RFC 1122
// §4.2.3.1 MUST — RFC 6298).
inline constexpr std::uint16_t kTcpRetransmissionTo04LocalOffset = 154U;

// §4.8.6.11 RETRANSMISSION_TO_05 active-OPEN port-quad offset. +155
// reserved slot continues the active-OPEN cluster reservation map
// (post-+154 RETRANSMISSION_TO_04). Same active-OPEN-no-listener
// shape as _06, but the SCXML chain observes 3 successive SYN
// retransmits with deltas anchored to Linux's 1 s / 2 s / 4 s
// exponential-backoff sequence — strictly proves "more than linear"
// because a constant-interval DUT fails the strict `> 1.5 s` gate
// at retx2 once the initial RTO is anchored at ~1 s by the retx1
// upper bound (RFC 1122 §4.2.3.1 MUST — RFC 6298 §5).
inline constexpr std::uint16_t kTcpRetransmissionTo05LocalOffset = 155U;

// §4.8.6.11 RETRANSMISSION_TO_03 active-OPEN port-quad offset. +156
// reserved slot continues the active-OPEN cluster reservation map
// (post-+155 RETRANSMISSION_TO_05). Verifies Karn's-algorithm
// doubling preservation (RFC 1122 §4.2.3.1 — Karn's): seg1 SEND →
// observe retx1 (RTO doubled to 2× initial) → state-entry-driven
// ACK injection acknowledging seg1 (ACK lands BEFORE retx2 fires
// per spec step 7) → seg2 SEND → observe retx2 with frame_delta_us
// > 300 ms verifying the DUT did NOT reset its RTO state on the
// Karn-recommended ACK (ambiguous-RTT ACK is excluded from RTT
// estimator per RFC 6298 §3 but icsk_rto stays at its doubled
// value).
inline constexpr std::uint16_t kTcpRetransmissionTo03LocalOffset = 156U;

// §4.8.6.19 CONTROL_FLAGS_08 passive listen + tester source quad
// (RFC 793 §3.4 figure 9 "old duplicate SYN" recovery). 13041 /
// kBasicsTesterPort+91 — well clear of the MSS_OPTIONS passive
// block (13002..13022) and the ACKNOWLEDGEMENT_03 listen (13030).
// The case raw-injects two SYNs from the same tester source on
// the same listen port; the figure 9 recovery path returns the
// DUT listener to LISTEN between SYNs so the second handshake
// reuses the 4-tuple without collision.
inline constexpr std::uint16_t kTcpControlFlags08ListenPort   = 13041U;
inline constexpr std::uint16_t kTcpControlFlags08TesterSrcPort
                                                     = kBasicsTesterPort + 91U;

// §4.8.6.19 CONTROL_FLAGS_08 phase 1 / phase 2 tester ISN values.
// SEQ1 = kTesterInitialSeq matches the §4.8 baseline tester SEQ;
// SEQ2 = SEQ1 + 0x10000 puts the second SYN's SEQ in a
// structurally distinct decade so the DUT's two SYN+ACK ack_num
// values (SEQ1+1 vs SEQ2+1) are visually distinguishable in pcap
// and the SCXML guard equality on each phase cannot accidentally
// satisfy the other phase's predicate. Chosen as compile-time
// constants rather than runtime captured fields because both
// phases issue raw-inject SYNs whose SEQ is fully tester-controlled
// — there is no kernel-driven seq snapshot to fold in.
inline constexpr std::uint32_t kTcpControlFlags08Seq1 = kTesterInitialSeq;
inline constexpr std::uint32_t kTcpControlFlags08Seq2 = kTesterInitialSeq + 0x10000U;

// §4.8.6.6 TCP_FLAGS_INVALID_02 probe ACK number. The tester's
// stimulus SYN+ACK to a LISTEN socket carries this value as
// SEG.ACK; per RFC 793 §3.9 p65 the DUT MUST respond with
// RST whose SEQ equals SEG.ACK, so the SCXML guard verifies
// `captured.seq_num == kFlagsInvalid02ProbeAck`. Chosen
// non-overlapping with kTesterInitialSeq + plausible offsets
// to make a misrouted DUT seq (e.g. RST.seq mirroring tester
// SEQ instead of tester ACK) a structurally distinct fail
// rather than silently passing the equality.
inline constexpr std::uint32_t kFlagsInvalid02ProbeAck = 0xCAFEBABEU;

// §4.8.6.17 TCP_SEQUENCE / §4.8.6.15 TCP_CONNECTION_ESTAB port-quad
// reservation block. Each subgroup case binds its own (listen_port,
// tester_src_port) — or per-CONN_ESTAB_03 (active local, tester remote)
// — so a TIME-WAIT residue from a sibling on the same worker netns
// does not collide with the next case's bind. Listen base 13160
// well clear of the §4.8.6.X HEADER passive block (13042..13050) and
// CONTROL_FLAGS_08 (13041); tester source base kBasicsTesterPort+160
// continues the §4.8 monotonic offset convention (RETRANSMISSION_TO
// peaks at +156, CONTROL_FLAGS_08 sits at +91).
inline constexpr std::uint16_t kTcpSequence01ListenPort     = 13160U;
inline constexpr std::uint16_t kTcpSequence01TesterSrcPort  = kBasicsTesterPort + 160U;
inline constexpr std::uint16_t kTcpSequence02LocalOffset    = 161U;
inline constexpr std::uint16_t kTcpSequence03ListenPort     = 13163U;
inline constexpr std::uint16_t kTcpSequence03TesterSrcPort  = kBasicsTesterPort + 163U;
inline constexpr std::uint16_t kTcpSequence04ListenPort     = 13164U;
inline constexpr std::uint16_t kTcpSequence04TesterSrcPort  = kBasicsTesterPort + 164U;
inline constexpr std::uint16_t kTcpSequence05ListenPort     = 13165U;
inline constexpr std::uint16_t kTcpSequence05TesterSrcPort  = kBasicsTesterPort + 165U;

// §4.8.6.15 CONNECTION_ESTAB_01 — single passive listener serving 3
// distinct tester source ports. The listen port is shared across
// the three SYN injects; the per-source port offsets keep each
// 4-tuple unique so the kernel demultiplexes the three handshakes.
inline constexpr std::uint16_t kTcpConnEstab01ListenPort     = 13170U;
inline constexpr std::uint16_t kTcpConnEstab01TesterSrcPort1 = kBasicsTesterPort + 170U;
inline constexpr std::uint16_t kTcpConnEstab01TesterSrcPort2 = kBasicsTesterPort + 171U;
inline constexpr std::uint16_t kTcpConnEstab01TesterSrcPort3 = kBasicsTesterPort + 172U;

// §4.8.6.15 CONNECTION_ESTAB_02 — three independent passive listeners,
// one tester source per listener. Distinct (listen_port,
// tester_src_port) per leg keeps the SCXML per-state guards clean.
inline constexpr std::uint16_t kTcpConnEstab02ListenPort1    = 13173U;
inline constexpr std::uint16_t kTcpConnEstab02ListenPort2    = 13174U;
inline constexpr std::uint16_t kTcpConnEstab02ListenPort3    = 13175U;
inline constexpr std::uint16_t kTcpConnEstab02TesterSrcPort1 = kBasicsTesterPort + 173U;
inline constexpr std::uint16_t kTcpConnEstab02TesterSrcPort2 = kBasicsTesterPort + 174U;
inline constexpr std::uint16_t kTcpConnEstab02TesterSrcPort3 = kBasicsTesterPort + 175U;

// §4.8.6.15 CONNECTION_ESTAB_03 — three active opens. Per-leg
// (DUT local, tester remote) offsets reuse the kBasicsActive*
// base so the active-OPEN port-quad collision rules
// (reference_active_open_port_quad_collision.md) stay intact.
inline constexpr std::uint16_t kTcpConnEstab03LocalOffset1   = 176U;
inline constexpr std::uint16_t kTcpConnEstab03LocalOffset2   = 177U;
inline constexpr std::uint16_t kTcpConnEstab03LocalOffset3   = 178U;

// §4.8.6.15 CONNECTION_ESTAB_07 — passive close path. Same shape
// as BASICS_03 but on a private listen port so cluster-wide cases
// running in parallel never collide on the BASICS_03 listen.
inline constexpr std::uint16_t kTcpConnEstab07ListenPort     = 13179U;

// §4.8.6.11 TCP_RETRANSMISSION_TO_08 — 2*MSL data-segment RTO upper
// bound (RFC 1122 §4.2.3.1 SHOULD). Linux's RTO_MAX = 120s
// compile-time constant ≠ spec's 2*MSL = 60s (Linux MSL = TCP_TIMEWAIT_LEN/2
// = 30s), so the case is expected to fail on a Linux DUT;
// strict-RFC DUT respecting 2*MSL=60s cap would pass. Wall-time
// budget capped via the case's poll-until-plateau loop so the
// envelope stays within the smoke regression budget instead of
// waiting for Linux's full ~200 s RTO_MAX path.
inline constexpr std::uint16_t kTcpRetransmissionTo08LocalOffset = 181U;

// §4.8.6.11 TCP_RETRANSMISSION_TO_09 — 2*MSL SYN-segment RTO upper
// bound. Same Linux RTO_MAX/2*MSL deviation as _08 plus the
// SYN-specific linear-then-exponential cadence (tcp_syn_linear_timeouts
// = 4 first 4 retries linear at 1 s, then exponential doubling).
inline constexpr std::uint16_t kTcpRetransmissionTo09LocalOffset = 182U;

// §4.8.6.2 TCP_CHECKSUM_04 — clock-driven ISN selection. Two active
// OPEN cycles on the same 4-tuple, each aborted by tester-kernel
// auto-RST against an unbound destination port. Same-port choice
// (rather than disjoint quads per cycle) actually exercises the
// "clock-driven" axis: with identical 4-tuples the secret-mixing
// term in Linux's `secure_tcp_seq` is constant across the two
// computations, so any ISN difference is sourced from the clock
// term. Disjoint-port quads would trivially differ via the secret
// path and fail to validate the spec's MUST.
inline constexpr std::uint16_t kTcpChecksum04LocalOffset     = 180U;

// §4.8.6.1 BASICS / §4.8.6.2 CHECKSUM / §4.8.6.6 FLAGS_INVALID_14 /
// §4.8.6.3 UNACCEPTABLE active-OPEN port-quad reservations (+200..+221).
// Each case (and each phase within a multi-phase case) binds a unique
// 4-tuple via its offset so a TIME-WAIT / LAST_ACK residue from a
// sibling on the same worker netns does not collide with the next
// case's bind. See `reference_active_open_port_quad_collision.md` for
// the BASICS_11 EADDRNOTAVAIL precedent that motivated this block —
// the prior per-case-unique pattern at +20..+25 / +50..+56 /
// +100..+182 is extended here to retire the last bare-port (offset 0)
// callers of `driveActiveOpenEstablished` / `driveTcpToTimeWaitFw2` /
// `driveCloseToTimeWaitClosing` / `driveCloseToClosing` (those four
// helpers no longer carry default port arguments — the compiler
// rejects any future caller that omits explicit ports).
//
// §4.8.6.1 BASICS_06..14 — UT-driven active-OPEN cluster. _08 / _10
// each chain two distinct active-OPEN handshakes per case, so they
// reserve two consecutive offsets. _11..14 chain post-CLOSE replay
// observations on the same 4-tuple as their drive prelude (single
// offset suffices).
inline constexpr std::uint16_t kTcpBasics06LocalOffset             = 200U;
inline constexpr std::uint16_t kTcpBasics07LocalOffset             = 201U;
inline constexpr std::uint16_t kTcpBasics08Phase1LocalOffset       = 202U;
inline constexpr std::uint16_t kTcpBasics08Phase2LocalOffset       = 203U;
inline constexpr std::uint16_t kTcpBasics09LocalOffset             = 204U;
inline constexpr std::uint16_t kTcpBasics10Phase1LocalOffset       = 205U;
inline constexpr std::uint16_t kTcpBasics10Phase2LocalOffset       = 206U;
inline constexpr std::uint16_t kTcpBasics11LocalOffset             = 207U;
inline constexpr std::uint16_t kTcpBasics12LocalOffset             = 208U;
inline constexpr std::uint16_t kTcpBasics13LocalOffset             = 209U;
inline constexpr std::uint16_t kTcpBasics14LocalOffset             = 210U;

// §4.8.6.2 CHECKSUM_01..03 — active-OPEN + raw-inject data + ACK
// observation. _04 already lives at +180 (clock-driven ISN axis
// requires same-port reuse) and is intentionally not in this block.
inline constexpr std::uint16_t kTcpChecksum01LocalOffset           = 211U;
inline constexpr std::uint16_t kTcpChecksum02LocalOffset           = 212U;
inline constexpr std::uint16_t kTcpChecksum03LocalOffset           = 213U;

// §4.8.6.6 FLAGS_INVALID_14 — two TIME-WAIT phases (FIN-flag OTW
// probe + data-segment OTW probe). Each phase runs its own
// driveTcpToTimeWaitFw2 prelude on a unique 4-tuple so the
// 78-second TIME-WAIT window does not collide between phases or
// with sibling cases on the same worker queue.
inline constexpr std::uint16_t kTcpFlagsInvalid14Phase1LocalOffset = 214U;
inline constexpr std::uint16_t kTcpFlagsInvalid14Phase2LocalOffset = 222U;

// §4.8.6.3 UNACCEPTABLE_04/_06/_09/_10/_13/_14 — active-OPEN +
// raw-inject sequences. _14 uses two phases on consecutive offsets so
// each phase's 4-tuple is unique even within the case.
inline constexpr std::uint16_t kTcpUnacceptable04LocalOffset       = 215U;
inline constexpr std::uint16_t kTcpUnacceptable06LocalOffset       = 216U;
inline constexpr std::uint16_t kTcpUnacceptable09Phase1LocalOffset = 217U;
inline constexpr std::uint16_t kTcpUnacceptable09Phase2LocalOffset = 223U;
inline constexpr std::uint16_t kTcpUnacceptable10LocalOffset       = 218U;
inline constexpr std::uint16_t kTcpUnacceptable13Phase1LocalOffset = 219U;
inline constexpr std::uint16_t kTcpUnacceptable13Phase2LocalOffset = 224U;
inline constexpr std::uint16_t kTcpUnacceptable14Phase1LocalOffset = 220U;
inline constexpr std::uint16_t kTcpUnacceptable14Phase2LocalOffset = 221U;

// Emit one TCP segment (IPv4-layer wrapped) on `iface`. Caller supplies
// the segment spec (flags / seq / ack / payload). Defaults to tester-
// side SEQ / tester source port so BASICS traits populate only the
// case-specific fields.
//
// `dut_mac` is required: Linux's TCP stack (net/ipv4/tcp_ipv4.c
// tcp_v4_rcv) gates on `skb->pkt_type == PACKET_HOST` and discards
// anything received on broadcast or multicast Ethernet destination.
// BASICS_04/05's closed-port RST response never fires unless the L2
// dst is the DUT's real MAC — the same gate §4.3 ICMP error replies
// hit (see `reference_icmp_packet_host_gate.md`). The Ipv4FrameSpec
// default of `kEthBroadcast` is wrong for TCP; forcing the caller to
// pass `dut_mac` explicitly prevents silent regressions.
//
// `payload` is the TCP data segment body (default empty). BASICS_04
// iteration 3 ("Data segment") populates this with a non-empty buffer
// so the spec literal "data segment with no ACK / no RST" is exercised
// at the wire — a zero-length data segment would still be a valid
// stimulus but would not distinguish iter 3 from iter 1's bare SYN at
// the segment-bytes level.
// Emit one fully-specified TCP segment. The caller controls every TCP
// header field (src/dst ports, SEQ, ACK, flags, options, payload, and
// the corrupt_tcp_checksum bit) via the TcpSegmentSpec. Cases needing
// only the BASICS-pilot defaults reach for the thinner emitTcpStimulus
// wrapper below; cases that vary tester-side ports across phases
// (e.g. §4.8.6.3 UNACCEPTABLE_01's two-probe sequence) build the spec
// directly.
inline void emitTcpFrame(const ::tc8::TestConfig &cfg,
                         std::string_view iface,
                         const std::array<std::uint8_t, 6> &dut_mac,
                         const ::tc8::stimulus::TcpSegmentSpec &spec,
                         std::chrono::milliseconds initial_wait =
                             kTcpPilotInitialWait) {
    const auto tcp_bytes = ::tc8::stimulus::buildTcpSegment(
        cfg.ipv4.tester_ip, cfg.ipv4.dut_iface_ip, spec);

    ::tc8::stimulus::Ipv4FrameSpec ip_spec{};
    ip_spec.dst_mac     = dut_mac;
    ip_spec.src_ip      = cfg.ipv4.tester_ip;
    ip_spec.dst_ip      = cfg.ipv4.dut_iface_ip;
    ip_spec.ip_protocol = ::tc8::stimulus::kIpProtoTcp;
    ::tc8::stimulus::IpBootTiming timing{};
    timing.initial_wait = initial_wait;
    ::tc8::stimulus::emitIpv4Frame(iface, ip_spec, tcp_bytes, timing);
}

inline void emitTcpStimulus(const ::tc8::TestConfig &cfg,
                            std::string_view iface,
                            const std::array<std::uint8_t, 6> &dut_mac,
                            std::uint16_t dst_port,
                            std::uint8_t  flags,
                            std::uint32_t seq_num = kTesterInitialSeq,
                            std::uint32_t ack_num = 0U,
                            std::vector<std::uint8_t> payload = {},
                            std::chrono::milliseconds initial_wait =
                                kTcpPilotInitialWait) {
    ::tc8::stimulus::TcpSegmentSpec tcp_spec{};
    tcp_spec.src_port = kBasicsTesterPort;
    tcp_spec.dst_port = dst_port;
    tcp_spec.seq_num  = seq_num;
    tcp_spec.ack_num  = ack_num;
    tcp_spec.flags    = flags;
    tcp_spec.payload  = std::move(payload);
    emitTcpFrame(cfg, iface, dut_mac, tcp_spec, initial_wait);
}

// Dispatch helper: select the TcpFrame variant, mirror into `c`, raise
// `tcp_observed` on the SM. Non-TCP events ignored.
//
// Inter-frame timing surface (auto-managed `prev_observed_ts_us`):
// `c.observed_ts_us` is updated unconditionally from the frame, but
// `c.prev_observed_ts_us` is snapshot ONLY when `sm.step()` advances
// `getCurrentState()` — i.e. when the transition guard fired and
// consumed the frame. This way `c.frame_delta_us()` always reads
// "delta since the last transition-firing frame", regardless of how
// many non-matching frames arrived between two state advancements.
// First-transition guards see `prev_observed_ts_us == 0` so
// `frame_delta_us()` returns 0 and the guard naturally evaluates only
// the structural conjuncts (flags / 4-tuple); second-and-later
// transitions see the stable per-frame interval. §4.8.6.11
// RETRANSMISSION_TO_04/_05/_06 + §4.8.6.12 PROBING_WINDOWS_06 depend
// on this contract.
template <typename SM>
inline void dispatchTcpFrame(typename SM::CapturedType &c, SM &sm,
                             const ::tc8::CapturedEvent &ev) {
    const auto *f = std::get_if<::tc8::TcpFrame>(&ev);
    if (f == nullptr) return;
    ::tc8::fillTcpCapturedFromFrame(c, *f);
    const auto state_before = sm.getCurrentState();
    sm.raiseExternal(SM::PolicyType::Event::Tcp_observed);
    sm.step();
    const auto state_after = sm.getCurrentState();
    if (state_after != state_before) {
        c.prev_observed_ts_us = c.observed_ts_us;
    }
}

// Boot-time UT initial wait. §4.8.5 TCP opcodes bind a fresh
// SOCK_STREAM per call, so the tc8-dut must have already completed
// its UT RPC bind (port 30600) before the tester's OpOpenTcpSocket
// reaches it. Same 1500 ms rationale as `kUdpPilotInitialWait`:
// vsomeip bootstrap + UT bind + harness-first smoke-test 500 ms
// grace. Shortening this makes BASICS_01..03 race-lose the UT bind
// and land on `fail_timeout` despite full DUT conformance.
inline constexpr auto kTcpUtBootWait = std::chrono::milliseconds(1500);

// Short wait between a UT TCP request and the follow-on tester action
// (connect / close / query). The tc8-dut processes the request
// synchronously in the UT server loop — bind + listen + spawn
// acceptor — so 100 ms absorbs recvmsg scheduling jitter on a loaded
// worker without burning wall time.
inline constexpr auto kTcpUtRpcWait = std::chrono::milliseconds(100);

// Grace window between the UT Active-OPEN RPC return and the moment
// the tester-side socket is ESTABLISHED. Linux completes the 3-way
// handshake on a same-host netns in single-digit milliseconds; 50 ms
// is the conservative ceiling across observed jitter on busy parallel
// workers. Used by `driveActiveOpenEstablished` so callers do not
// duplicate the magic-number sleep at every active-open prelude.
inline constexpr auto kTcpActiveHandshakeGrace = std::chrono::milliseconds(50);

// Inline UT request sender. Wraps the opcode-specific builder and the
// raw-inject path in one line so BASICS traits stay a clean sequence
// of "open socket, connect, query established, close socket".
//
// Two flavours mirror the §4.8.5 `<openTCPSocket(typeOfSocket=…)>`
// procedure split. Passive opens a DUT-side listener (BASICS_01..03,
// 09, 10's prep stage); active drives the DUT to issue its own SYN
// (BASICS_06..08).
inline int sendOpenTcpSocketPassiveRequest(
    const ::tc8::TestConfig &cfg,
    std::string_view iface,
    const std::array<std::uint8_t, 6> &dut_mac,
    std::uint8_t  req_id,
    std::uint16_t local_port,
    std::uint16_t tester_src_port = ::tc8::ut::kTesterSrcPort) {
    const auto payload =
        ::tc8::stimulus::buildOpenTcpSocketPassiveRequest(req_id, local_port);
    return ::tc8::stimulus::sendUpperTesterRequest(
        iface, cfg.ipv4.tester_ip, cfg.ipv4.dut_iface_ip, dut_mac,
        tester_src_port, payload);
}

inline int sendOpenTcpSocketActiveRequest(
    const ::tc8::TestConfig &cfg,
    std::string_view iface,
    const std::array<std::uint8_t, 6> &dut_mac,
    std::uint8_t  req_id,
    std::uint16_t local_port,
    std::uint32_t remote_ip_be,
    std::uint16_t remote_port,
    std::uint16_t tester_src_port = ::tc8::ut::kTesterSrcPort) {
    const auto payload = ::tc8::stimulus::buildOpenTcpSocketActiveRequest(
        req_id, local_port, remote_ip_be, remote_port);
    return ::tc8::stimulus::sendUpperTesterRequest(
        iface, cfg.ipv4.tester_ip, cfg.ipv4.dut_iface_ip, dut_mac,
        tester_src_port, payload);
}

inline int sendCloseTcpSocketRequest(const ::tc8::TestConfig &cfg,
                                     std::string_view iface,
                                     const std::array<std::uint8_t, 6> &dut_mac,
                                     std::uint8_t req_id,
                                     std::uint8_t socket_id,
                                     std::uint16_t tester_src_port = ::tc8::ut::kTesterSrcPort) {
    const auto payload = ::tc8::stimulus::buildCloseTcpSocketRequest(req_id, socket_id);
    return ::tc8::stimulus::sendUpperTesterRequest(
        iface, cfg.ipv4.tester_ip, cfg.ipv4.dut_iface_ip, dut_mac,
        tester_src_port, payload);
}

inline int sendShutdownTcpSocketWrRequest(const ::tc8::TestConfig &cfg,
                                           std::string_view iface,
                                           const std::array<std::uint8_t, 6> &dut_mac,
                                           std::uint8_t  req_id,
                                           std::uint8_t  socket_id,
                                           std::uint16_t tester_src_port = ::tc8::ut::kTesterSrcPort) {
    const auto payload = ::tc8::stimulus::buildShutdownTcpSocketWrRequest(req_id, socket_id);
    return ::tc8::stimulus::sendUpperTesterRequest(
        iface, cfg.ipv4.tester_ip, cfg.ipv4.dut_iface_ip, dut_mac,
        tester_src_port, payload);
}

// §4.8.6.5 CALL_ABORT_02/_03 driver: ask tc8-dut to issue an ABORT
// (SO_LINGER {1,0} + close) on the previously-opened socket. tc8-dut
// emits RST on the wire and removes the socket_id from its listener
// map; subsequent UT calls on the id collapse to kStatusUnknownSocket.
inline int sendAbortTcpSocketRequest(const ::tc8::TestConfig &cfg,
                                     std::string_view iface,
                                     const std::array<std::uint8_t, 6> &dut_mac,
                                     std::uint8_t  req_id,
                                     std::uint8_t  socket_id,
                                     std::uint16_t tester_src_port = ::tc8::ut::kTesterSrcPort) {
    const auto payload = ::tc8::stimulus::buildAbortTcpSocketRequest(req_id, socket_id);
    return ::tc8::stimulus::sendUpperTesterRequest(
        iface, cfg.ipv4.tester_ip, cfg.ipv4.dut_iface_ip, dut_mac,
        tester_src_port, payload);
}

inline int sendQueryTcpEstablishedRequest(const ::tc8::TestConfig &cfg,
                                          std::string_view iface,
                                          const std::array<std::uint8_t, 6> &dut_mac,
                                          std::uint8_t req_id,
                                          std::uint8_t socket_id,
                                          std::uint16_t tester_src_port = ::tc8::ut::kTesterSrcPort) {
    const auto payload = ::tc8::stimulus::buildQueryTcpEstablishedRequest(req_id, socket_id);
    return ::tc8::stimulus::sendUpperTesterRequest(
        iface, cfg.ipv4.tester_ip, cfg.ipv4.dut_iface_ip, dut_mac,
        tester_src_port, payload);
}

// §4.8.6.2 CHECKSUM_03 driver: ask tc8-dut to write `payload` bytes
// onto the previously-opened connected fd. The DUT-emitted segment
// falls out of Linux's TCP stack with a correct pseudo-header
// checksum, observable on pcap.
inline int sendSendTcpDataRequest(const ::tc8::TestConfig &cfg,
                                  std::string_view iface,
                                  const std::array<std::uint8_t, 6> &dut_mac,
                                  std::uint8_t        req_id,
                                  std::uint8_t        socket_id,
                                  const std::uint8_t *payload,
                                  std::uint16_t       payload_len,
                                  std::uint16_t tester_src_port = ::tc8::ut::kTesterSrcPort) {
    const auto buf = ::tc8::stimulus::buildSendTcpDataRequest(
        req_id, socket_id, payload, payload_len);
    return ::tc8::stimulus::sendUpperTesterRequest(
        iface, cfg.ipv4.tester_ip, cfg.ipv4.dut_iface_ip, dut_mac,
        tester_src_port, buf);
}

// §4.8.6.9 MSS_OPTIONS_06/_09/_10 driver: ask tc8-dut to allocate
// `total_len` bytes filled with `pattern` and write them onto the
// connected fd. Used to drive Linux's TCP segmentation with bulk
// data — payload count exceeds MTU so the kernel segments per the
// negotiated send MSS.
inline int sendSendTcpDataPatternRequest(
    const ::tc8::TestConfig &cfg,
    std::string_view iface,
    const std::array<std::uint8_t, 6> &dut_mac,
    std::uint8_t  req_id,
    std::uint8_t  socket_id,
    std::uint8_t  pattern,
    std::uint16_t total_len,
    std::uint16_t tester_src_port = ::tc8::ut::kTesterSrcPort) {
    const auto buf = ::tc8::stimulus::buildSendTcpDataPatternRequest(
        req_id, socket_id, pattern, total_len);
    return ::tc8::stimulus::sendUpperTesterRequest(
        iface, cfg.ipv4.tester_ip, cfg.ipv4.dut_iface_ip, dut_mac,
        tester_src_port, buf);
}

// Tester-side `connect()` to the DUT's listener. Uses the tester
// netns's normal socket layer, so the kernel issues its own SYN
// (with kernel-chosen SEQ) and completes the 3-way handshake end-
// to-end. BASICS_01/02/03 pass criteria observe DUT-origin segments
// which fall out of this handshake naturally — the tester's outbound
// SYN and ACK are filtered out in the SCXML by src_ip mismatch.
//
// `post_close` controls tester-side teardown:
//   * kKeepOpen  — leave the socket connected (BASICS_02: wait for UT
//     OpQueryTcpEstablished to flip, then close at stimulus end).
//   * kShutdownWr — shutdown(SHUT_WR) to send FIN without close (used
//     by BASICS_03 as the TESTER FIN,ACK step).
//   * kClose      — close immediately (BASICS_01: socket not needed
//     past the SYN+ACK observation).
//
// Returns 0 on success, -1 on any syscall failure. Prints errno on
// failure so smoke-test debug logs show the root cause instead of
// silent "connect returned non-zero".
// Synchronous UT OpQueryTcpEstablished. Opens a transient UDP socket,
// sends the query to DUT:30600, waits up to 500 ms for the
// Confirmation, returns the `established` byte parsed from the
// response body.
//
// Returns:
//   0x01 — established (DUT listener has accepted a connection),
//   0x00 — not established,
//   0xFF — any RPC failure (socket, send, recv timeout, malformed
//          response). BASICS_02 treats 0xFF as a hard-failure path
//          (same class as "no SYN+ACK within listen window"), so the
//          tristate is deterministic.
inline std::uint8_t queryTcpEstablishedSync(const ::tc8::TestConfig &cfg,
                                            std::uint8_t req_id,
                                            std::uint8_t socket_id,
                                            std::chrono::milliseconds timeout =
                                                std::chrono::milliseconds(500)) {
    const int fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) return 0xFFU;
    timeval tv{};
    tv.tv_sec  = static_cast<time_t>(timeout.count() / 1000);
    tv.tv_usec = static_cast<suseconds_t>((timeout.count() % 1000) * 1000);
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in remote{};
    remote.sin_family      = AF_INET;
    remote.sin_addr.s_addr = cfg.ipv4.dut_iface_ip;
    remote.sin_port        = htons(::tc8::ut::kPort);

    const auto payload = ::tc8::stimulus::buildQueryTcpEstablishedRequest(
        req_id, socket_id);
    if (::sendto(fd, payload.data(), payload.size(), 0,
                 reinterpret_cast<sockaddr*>(&remote), sizeof(remote))
        != static_cast<ssize_t>(payload.size())) {
        ::close(fd);
        return 0xFFU;
    }

    std::uint8_t buf[64];
    sockaddr_in peer{};
    socklen_t peer_len = sizeof(peer);
    const ssize_t n = ::recvfrom(fd, buf, sizeof(buf), 0,
                                  reinterpret_cast<sockaddr*>(&peer), &peer_len);
    ::close(fd);
    // Expected: <0x85 (response opcode)> <req_id> <status=0x00> <established:u8>.
    if (n < 4) return 0xFFU;
    if (buf[0] != static_cast<std::uint8_t>(::tc8::ut::OpQueryTcpEstablished
                                            | ::tc8::ut::kResponseBit)) return 0xFFU;
    if (buf[1] != req_id)                                              return 0xFFU;
    if (buf[2] != ::tc8::ut::kStatusOk)                                return 0xFFU;
    return buf[3];
}

// §4.8.6.11 RETRANSMISSION_TO kernel-side TCP_INFO snapshot returned
// by `queryTcpInfoSync`. Mirrors the four `struct tcp_info` fields
// the §4.8.6.11 cluster verdicts on; see the `OpQueryTcpInfo`
// documentation in `include/tc8/upper_tester_protocol.h`. `valid`
// is false on any RPC failure (socket / send / recv timeout /
// malformed response / unknown socket on the tc8-dut side) so the
// caller treats every non-success path as "no kernel state to
// report" and the SCXML guard chain trips a fail_query verdict.
struct TcpInfoSnapshot {
    bool          valid       = false;
    std::uint8_t  state       = 0U;  // tcpi_state (1=ESTABLISHED, ...)
    std::uint32_t rto_us      = 0U;  // tcpi_rto in microseconds
    std::uint8_t  retransmits = 0U;  // tcpi_retransmits
    std::uint32_t unacked     = 0U;  // tcpi_unacked (tp->packets_out)
};

// Synchronous UT OpQueryTcpInfo (0x13). Opens a transient UDP
// socket, sends the query to DUT:30600, waits up to `timeout` for
// the Confirmation, and returns a TcpInfoSnapshot. Used by §4.8.6.11
// TCP_RETRANSMISSION_TO_03's stimulus to verdict RFC 6298 RTO
// behaviour off kernel state instead of pcap timing — eliminating
// the dependency on pcap delivering retransmits within tight wall-
// clock windows under `--workers >= 2` parallel load.
inline TcpInfoSnapshot queryTcpInfoSync(const ::tc8::TestConfig &cfg,
                                        std::uint8_t req_id,
                                        std::uint8_t socket_id,
                                        std::chrono::milliseconds timeout =
                                            std::chrono::milliseconds(500)) {
    TcpInfoSnapshot snap{};
    const int fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) return snap;
    timeval tv{};
    tv.tv_sec  = static_cast<time_t>(timeout.count() / 1000);
    tv.tv_usec = static_cast<suseconds_t>((timeout.count() % 1000) * 1000);
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in remote{};
    remote.sin_family      = AF_INET;
    remote.sin_addr.s_addr = cfg.ipv4.dut_iface_ip;
    remote.sin_port        = htons(::tc8::ut::kPort);

    const auto payload = ::tc8::stimulus::buildQueryTcpInfoRequest(
        req_id, socket_id);
    if (::sendto(fd, payload.data(), payload.size(), 0,
                 reinterpret_cast<sockaddr*>(&remote), sizeof(remote))
        != static_cast<ssize_t>(payload.size())) {
        ::close(fd);
        return snap;
    }

    std::uint8_t buf[64];
    sockaddr_in peer{};
    socklen_t peer_len = sizeof(peer);
    const ssize_t n = ::recvfrom(fd, buf, sizeof(buf), 0,
                                  reinterpret_cast<sockaddr*>(&peer), &peer_len);
    ::close(fd);
    // Expected: <0x93 (response opcode)> <req_id> <status=0x00>
    //           <state:u8> <rto_us:u32 BE> <retransmits:u8>
    //           <unacked:u32 BE>. 13 bytes total.
    if (n < 13) return snap;
    if (buf[0] != static_cast<std::uint8_t>(::tc8::ut::OpQueryTcpInfo
                                            | ::tc8::ut::kResponseBit)) return snap;
    if (buf[1] != req_id)                                              return snap;
    if (buf[2] != ::tc8::ut::kStatusOk)                                return snap;
    snap.valid       = true;
    snap.state       = buf[3];
    snap.rto_us      = (static_cast<std::uint32_t>(buf[4]) << 24)
                     | (static_cast<std::uint32_t>(buf[5]) << 16)
                     | (static_cast<std::uint32_t>(buf[6]) << 8)
                     |  static_cast<std::uint32_t>(buf[7]);
    snap.retransmits = buf[8];
    snap.unacked     = (static_cast<std::uint32_t>(buf[9])  << 24)
                     | (static_cast<std::uint32_t>(buf[10]) << 16)
                     | (static_cast<std::uint32_t>(buf[11]) << 8)
                     |  static_cast<std::uint32_t>(buf[12]);
    return snap;
}

// Synchronous UT OpReceiveTcpData. Sends the request, blocks for the
// Confirmation (which itself blocks in tc8-dut until expected_len
// bytes arrive on the connected fd or `timeout_ms` elapses), and
// returns the bytes the tc8-dut read. Empty return ⇒ unknown
// socket / tc8-dut got 0 bytes / RPC failure (the three are
// indistinguishable to the caller; empty short-circuits to "didn't
// receive proper data" at the SCXML guard).
//
// The tester-side recvfrom timeout = timeout_ms + 500 ms so the UT
// RPC reply has headroom past the tc8-dut blocking window. No
// retries — TC8_CLOSING_07/_08 expect a single recv-and-respond
// cycle within the SCXML observation deadline.
inline std::vector<std::uint8_t> queryReceivedBytesSync(
    const ::tc8::TestConfig &cfg,
    std::uint8_t  req_id,
    std::uint8_t  socket_id,
    std::uint16_t expected_len,
    std::uint16_t timeout_ms) {
    const int fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) return {};

    timeval tv{};
    const long total_ms = static_cast<long>(timeout_ms) + 500L;
    tv.tv_sec  = static_cast<time_t>(total_ms / 1000);
    tv.tv_usec = static_cast<suseconds_t>((total_ms % 1000) * 1000);
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in remote{};
    remote.sin_family      = AF_INET;
    remote.sin_addr.s_addr = cfg.ipv4.dut_iface_ip;
    remote.sin_port        = htons(::tc8::ut::kPort);

    const auto payload = ::tc8::stimulus::buildReceiveTcpDataRequest(
        req_id, socket_id, expected_len, timeout_ms);
    if (::sendto(fd, payload.data(), payload.size(), 0,
                 reinterpret_cast<sockaddr*>(&remote), sizeof(remote))
        != static_cast<ssize_t>(payload.size())) {
        ::close(fd);
        return {};
    }

    // 3-byte header (opcode|0x80, req_id, status) + 2-byte received_len
    // + up to kMaxPayload bytes. Use kMaxPayload as cap.
    std::uint8_t buf[5 + ::tc8::ut::kMaxPayload];
    sockaddr_in peer{};
    socklen_t peer_len = sizeof(peer);
    const ssize_t n = ::recvfrom(fd, buf, sizeof(buf), 0,
                                  reinterpret_cast<sockaddr*>(&peer), &peer_len);
    ::close(fd);

    if (n < 5) return {};
    if (buf[0] != static_cast<std::uint8_t>(::tc8::ut::OpReceiveTcpData
                                            | ::tc8::ut::kResponseBit)) return {};
    if (buf[1] != req_id)                                               return {};
    if (buf[2] != ::tc8::ut::kStatusOk)                                 return {};
    const std::uint16_t received_len =
        static_cast<std::uint16_t>((buf[3] << 8) | buf[4]);
    if (5 + received_len > n) return {};
    return std::vector<std::uint8_t>(buf + 5, buf + 5 + received_len);
}

// Synchronous UT OpReceiveTcpDataOob. Same shape as
// queryReceivedBytesSync — the only difference is the request
// opcode the tc8-dut uses to dispatch to recv(MSG_OOB) vs recv(0).
// Returns the bytes Linux's OOB queue surfaced (1 byte per URG
// segment under default sysctl_tcp_stdurg=0); empty vector on RPC
// failure / unknown socket / timeout.
inline std::vector<std::uint8_t> queryReceivedBytesOobSync(
    const ::tc8::TestConfig &cfg,
    std::uint8_t  req_id,
    std::uint8_t  socket_id,
    std::uint16_t expected_len,
    std::uint16_t timeout_ms) {
    const int fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) return {};

    timeval tv{};
    const long total_ms = static_cast<long>(timeout_ms) + 500L;
    tv.tv_sec  = static_cast<time_t>(total_ms / 1000);
    tv.tv_usec = static_cast<suseconds_t>((total_ms % 1000) * 1000);
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in remote{};
    remote.sin_family      = AF_INET;
    remote.sin_addr.s_addr = cfg.ipv4.dut_iface_ip;
    remote.sin_port        = htons(::tc8::ut::kPort);

    const auto payload = ::tc8::stimulus::buildReceiveTcpDataOobRequest(
        req_id, socket_id, expected_len, timeout_ms);
    if (::sendto(fd, payload.data(), payload.size(), 0,
                 reinterpret_cast<sockaddr*>(&remote), sizeof(remote))
        != static_cast<ssize_t>(payload.size())) {
        ::close(fd);
        return {};
    }

    std::uint8_t buf[5 + ::tc8::ut::kMaxPayload];
    sockaddr_in peer{};
    socklen_t peer_len = sizeof(peer);
    const ssize_t n = ::recvfrom(fd, buf, sizeof(buf), 0,
                                  reinterpret_cast<sockaddr*>(&peer), &peer_len);
    ::close(fd);

    if (n < 5) return {};
    if (buf[0] != static_cast<std::uint8_t>(::tc8::ut::OpReceiveTcpDataOob
                                            | ::tc8::ut::kResponseBit)) return {};
    if (buf[1] != req_id)                                               return {};
    if (buf[2] != ::tc8::ut::kStatusOk)                                 return {};
    const std::uint16_t received_len =
        static_cast<std::uint16_t>((buf[3] << 8) | buf[4]);
    if (5 + received_len > n) return {};
    return std::vector<std::uint8_t>(buf + 5, buf + 5 + received_len);
}

// Tester-side TCP listener. BASICS_06+ active-open cases need the
// tester to bind+listen on `kBasicsActiveRemotePort` so the DUT's
// connect() lands on a real listening socket — without this the
// tester kernel would respond with RST under
// `tcp_v4_send_reset`, the DUT's connect() would fail, and the test
// case would observe one SYN followed by an immediate RST exchange
// instead of the full handshake.
//
// RAII: ctor creates the listener; dtor closes the fd. Move-only so
// stimulus stack-locals can transfer ownership without inviting double-
// close on copy. accept() runs on a one-shot worker so the ctor
// returns immediately — the spec assertion is "DUT emits SYN", not
// "tester accepts the connection", so the helper does not block
// stimulus on accept().
class TesterTcpListener {
public:
    explicit TesterTcpListener(std::uint16_t port,
                                int backlog = kBasicsTesterListenBacklog) {
        fd_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fd_ < 0) return;
        int on = 1;
        ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        // SO_REUSEPORT covers a quirk SO_REUSEADDR alone does not: a
        // prior case's accepted socket goes to TIME_WAIT bound to
        // (tester_ip, port); a fresh INADDR_ANY:port bind by the next
        // case is rejected EADDRINUSE because ANY:port is "specific
        // ip + port" relative to the TIME_WAIT entry. SO_REUSEPORT
        // (a single-process variant of REUSEADDR — see
        // socket(7) NOTES) lifts that block. §4.8.6.2 CHECKSUM_02
        // exposes this between consecutive cases binding the same
        // listener port, but the option is benign for §4.8.6.1
        // BASICS_06+ which only need REUSEADDR semantics.
        ::setsockopt(fd_, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port        = htons(port);
        if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            std::fprintf(stderr,
                         "tcp-pilot: tester listen bind port %u failed: %d\n",
                         port, errno);
            ::close(fd_);
            fd_ = -1;
            return;
        }
        if (::listen(fd_, backlog) < 0) {
            std::fprintf(stderr,
                         "tcp-pilot: tester listen() on port %u failed: %d\n",
                         port, errno);
            ::close(fd_);
            fd_ = -1;
        }
    }
    ~TesterTcpListener() { close(); }

    TesterTcpListener(const TesterTcpListener &)            = delete;
    TesterTcpListener &operator=(const TesterTcpListener &) = delete;
    TesterTcpListener(TesterTcpListener &&other) noexcept : fd_(other.fd_) {
        other.fd_ = -1;
    }
    TesterTcpListener &operator=(TesterTcpListener &&other) noexcept {
        if (this != &other) { close(); fd_ = other.fd_; other.fd_ = -1; }
        return *this;
    }

    bool ok() const { return fd_ >= 0; }
    int  fd() const { return fd_; }

    // Accept one queued connection, polling for up to `timeout`. Returns
    // the connected fd on success, -1 on timeout or accept failure. The
    // caller owns the returned fd (RAII handoff to the caller's local).
    //
    // Used by BASICS_08+ to grab the tester-side end of the DUT's
    // active-open handshake so a deliberate FIN (shutdown(SHUT_WR))
    // can be issued at a precise point in the test procedure — Linux's
    // automatic listener accept-queue plumbing completes the SYN+ACK
    // round trip but provides no API for sending application-driven
    // FIN until accept() materialises a userland fd.
    int acceptOne(std::chrono::milliseconds timeout =
                       std::chrono::milliseconds(1000)) {
        if (fd_ < 0) return -1;
        pollfd pfd{};
        pfd.fd     = fd_;
        pfd.events = POLLIN;
        const int rc = ::poll(&pfd, 1, static_cast<int>(timeout.count()));
        if (rc <= 0 || (pfd.revents & POLLIN) == 0) return -1;
        sockaddr_in peer{};
        socklen_t   peer_len = sizeof(peer);
        return ::accept(fd_, reinterpret_cast<sockaddr*>(&peer), &peer_len);
    }

    void close() {
        if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
    }

private:
    int fd_ = -1;
};

// Tester-side TCP sequence-number snapshot. CHECKSUM_02's raw-inject
// path needs SEQ/ACK values that fall inside the DUT's receive window;
// otherwise Linux's `tcp_v4_rcv` drops the segment for being out-of-
// window before ever consulting the checksum, and the absence-of-ACK
// observation would prove "out-of-window drop", not "checksum drop".
//
// `snd_nxt` is the SEQ the kernel would use if it sent the next byte
// itself — i.e. the value the DUT is expecting next. `rcv_nxt` is the
// ACK number the tester would place on its next outbound ACK,
// mirroring what the DUT has already transmitted. Together they give
// the raw-inject builder a correct (SEQ=snd_nxt, ACK=rcv_nxt) pair
// without any guesswork.
//
// Linux's `struct tcp_info` from <linux/tcp.h> does not expose these
// fields directly (TCP_INFO carries metrics, not raw queue state).
// Reading them requires TCP_REPAIR mode + TCP_QUEUE_SEQ, which freezes
// the socket briefly: caller must not invoke ::send / ::recv between
// the open and close of repair mode. CAP_NET_ADMIN is required; the
// smoke-test runs as root inside its netns, so the call always
// succeeds on the supported topology.
struct TcpSeqRange {
    std::uint32_t snd_nxt = 0;
    std::uint32_t rcv_nxt = 0;
};

inline std::optional<TcpSeqRange> queryTcpSeqRange(int fd) {
    if (fd < 0) return std::nullopt;

    int repair_on = 1;
    if (::setsockopt(fd, IPPROTO_TCP, TCP_REPAIR, &repair_on, sizeof(repair_on)) < 0) {
        return std::nullopt;
    }

    TcpSeqRange r{};
    bool ok = true;

    // TCP_SEND_QUEUE → snd_nxt: the SEQ the kernel will use on the
    // next byte it transmits. Equal to (ISN_tester + 1 + bytes_sent_so_far).
    int queue = TCP_SEND_QUEUE;
    socklen_t len = sizeof(r.snd_nxt);
    if (::setsockopt(fd, IPPROTO_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue)) < 0 ||
        ::getsockopt(fd, IPPROTO_TCP, TCP_QUEUE_SEQ, &r.snd_nxt, &len) < 0) {
        ok = false;
    }

    // TCP_RECV_QUEUE → rcv_nxt: the next SEQ the kernel expects to
    // receive from the peer = (ISN_dut + 1 + bytes_received_so_far).
    queue = TCP_RECV_QUEUE;
    len = sizeof(r.rcv_nxt);
    if (ok && (::setsockopt(fd, IPPROTO_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue)) < 0 ||
               ::getsockopt(fd, IPPROTO_TCP, TCP_QUEUE_SEQ, &r.rcv_nxt, &len) < 0)) {
        ok = false;
    }

    // TCP_REPAIR_OFF — exit repair mode without window-probing the
    // peer. _OFF_NO_WP avoids generating spurious traffic during the
    // exit; for a connection that hasn't moved bytes since the
    // handshake, the alternative TCP_REPAIR_OFF (= 0, with WP) is
    // also safe but emits a probe we don't need.
    int repair_off = TCP_REPAIR_OFF_NO_WP;
    ::setsockopt(fd, IPPROTO_TCP, TCP_REPAIR, &repair_off, sizeof(repair_off));

    if (!ok) return std::nullopt;
    return r;
}

enum class TcpPostClose { kClose, kShutdownWr, kKeepOpen };

inline int connectToDutTcp(const ::tc8::TestConfig &cfg,
                           std::uint16_t dst_port,
                           TcpPostClose post_close,
                           int *out_fd = nullptr) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        std::fprintf(stderr, "tcp-pilot: socket() failed: %d\n", errno);
        return -1;
    }

    sockaddr_in remote{};
    remote.sin_family      = AF_INET;
    remote.sin_addr.s_addr = cfg.ipv4.dut_iface_ip;
    remote.sin_port        = htons(dst_port);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&remote), sizeof(remote)) < 0) {
        std::fprintf(stderr, "tcp-pilot: connect() to port %u failed: %d\n",
                     dst_port, errno);
        ::close(fd);
        return -1;
    }

    if (post_close == TcpPostClose::kShutdownWr) {
        ::shutdown(fd, SHUT_WR);
        // Leave the fd open — tester read-side stays up to consume
        // the DUT's FIN,ACK without the kernel RST-ing on closed-fd
        // arrival. Caller is responsible for eventual close().
        if (out_fd != nullptr) *out_fd = fd;
        return 0;
    }
    if (post_close == TcpPostClose::kKeepOpen) {
        if (out_fd != nullptr) *out_fd = fd;
        return 0;
    }
    ::close(fd);
    if (out_fd != nullptr) *out_fd = -1;
    return 0;
}

// Dedicated iptables chain housing every tester-side suppression rule
// the stimulus RAIIs below install. Rules NEVER go directly into
// OUTPUT: a SIGKILLed harness skips the RAII destructors, and a rule
// leaked into OUTPUT silently poisons every later TCP exchange against
// the DUT on topologies whose tester kernel persists across runs
// (external / ssh-remote; single-pc discards the per-case netns). With
// one well-known chain, smoke-test.sh flushes the leaks at bring-up
// without knowing any rule shape. The OUTPUT->chain jump itself is
// idempotent permanent residue, inert while the chain is empty.
inline constexpr const char *kTesterStimulusChain = "tc8-stimulus";

inline bool ensureTesterStimulusChain() {
    char cmd[160];
    std::snprintf(cmd, sizeof(cmd),
                  "iptables -w 5 -nL %s >/dev/null 2>&1 || "
                  "iptables -w 5 -N %s 2>/dev/null",
                  kTesterStimulusChain, kTesterStimulusChain);
    if (std::system(cmd) != 0) return false;
    std::snprintf(cmd, sizeof(cmd),
                  "iptables -w 5 -C OUTPUT -j %s 2>/dev/null || "
                  "iptables -w 5 -A OUTPUT -j %s 2>/dev/null",
                  kTesterStimulusChain, kTesterStimulusChain);
    return std::system(cmd) == 0;
}

// Suppress tester-kernel auto-RST against the DUT for the lifetime
// of the scope. The Linux tester kernel responds with RST to any
// inbound TCP segment that does not match a known socket — for
// raw-injected handshakes (UNACCEPTABLE_03 syn-recv probe,
// UNACCEPTABLE_08 syn-sent probe) this would race-kill the DUT's
// embryonic state before the test stimulus emits its bad-ACK
// follow-up. The iptables rule drops RST traffic toward the DUT IP
// for the scope's lifetime, inside the kTesterStimulusChain chain.
//
// The scope owns the rule via RAII: constructor runs `iptables -A`,
// destructor runs `iptables -D`. Smoke-test runs as root inside its
// netns, so the rule installs without sudo. Failure to install is
// non-fatal — the stimulus continues and any race condition surfaces
// as a deterministic case timeout, not a silent hang.
class TesterAutoRstDrop {
public:
    explicit TesterAutoRstDrop(const ::tc8::TestConfig &cfg) {
        char dut_ip[INET_ADDRSTRLEN] = {};
        if (::inet_ntop(AF_INET, &cfg.ipv4.dut_iface_ip, dut_ip,
                         sizeof(dut_ip)) == nullptr) {
            return;
        }
        char cmd[256];
        // `-w 5`: serialise concurrent smoke-test workers on the
        // global xtables lock. Defensive across both iptables-legacy
        // (/run/xtables.lock) and iptables-nft (netlink-layer
        // serialisation) backends.
        if (!ensureTesterStimulusChain()) {
            std::fprintf(stderr,
                         "tcp-pilot: TesterAutoRstDrop chain setup failed "
                         "(continuing without RST suppression)\n");
            return;
        }
        const int rc = std::snprintf(cmd, sizeof(cmd),
                      "iptables -w 5 -A %s -p tcp --tcp-flags RST RST "
                      "-d %s -j DROP 2>/dev/null",
                      kTesterStimulusChain, dut_ip);
        if (rc < 0 || rc >= static_cast<int>(sizeof(cmd))) return;
        if (std::system(cmd) == 0) {
            installed_ = true;
            dut_ip_.assign(dut_ip);
        } else {
            std::fprintf(stderr,
                         "tcp-pilot: TesterAutoRstDrop install failed "
                         "(continuing without RST suppression)\n");
        }
    }

    ~TesterAutoRstDrop() {
        if (!installed_) return;
        char cmd[256];
        std::snprintf(cmd, sizeof(cmd),
                      "iptables -w 5 -D %s -p tcp --tcp-flags RST RST "
                      "-d %s -j DROP 2>/dev/null",
                      kTesterStimulusChain, dut_ip_.c_str());
        int rc = std::system(cmd);
        (void)rc;
    }

    TesterAutoRstDrop(const TesterAutoRstDrop &)            = delete;
    TesterAutoRstDrop &operator=(const TesterAutoRstDrop &) = delete;

    bool installed() const { return installed_; }

private:
    bool installed_ = false;
    std::string dut_ip_;
};

// Suppress tester-kernel pure ACKs toward the DUT for the lifetime of
// the scope. §4.8.6.3 UNACCEPTABLE_09 / _12 require the DUT to remain
// in FIN-WAIT-1 / LAST-ACK while the corrupt-segment stimulus arrives;
// without this rule, the tester's automatic ACK to the DUT-emitted FIN
// advances the DUT into FIN-WAIT-2 / CLOSED before the spec-asserted
// edge can fire. The match is "ACK only" (FIN, SYN, RST clear; ACK
// set) so SYN+ACK during handshake and tester FIN/RST segments pass
// through unaffected. The injected corrupt segments carry PSH+ACK
// with payload, so they also do not match the rule. Installed inside
// kTesterStimulusChain like every stimulus suppression rule.
//
// The scope owns the rule via RAII: constructor runs `iptables -A`,
// destructor runs `iptables -D`. Smoke-test runs as root inside its
// netns, so the rule installs without sudo. Failure to install is
// non-fatal — the stimulus continues and the case surfaces as a
// deterministic FIN-WAIT-2 collapse on pcap rather than a silent hang.
class TesterAutoAckDrop {
public:
    explicit TesterAutoAckDrop(const ::tc8::TestConfig &cfg) {
        char dut_ip[INET_ADDRSTRLEN] = {};
        if (::inet_ntop(AF_INET, &cfg.ipv4.dut_iface_ip, dut_ip,
                         sizeof(dut_ip)) == nullptr) {
            return;
        }
        char cmd[256];
        // `-w 5`: serialise concurrent smoke-test workers on the
        // global xtables lock. Linux iptables-1.6+ supports `-w` plus
        // an optional timeout in seconds. iptables-legacy uses
        // /run/xtables.lock; iptables-nft serialises at the netlink
        // layer instead. Defensive across both backends.
        if (!ensureTesterStimulusChain()) {
            std::fprintf(stderr,
                         "tcp-pilot: TesterAutoAckDrop chain setup failed "
                         "(continuing without ACK suppression)\n");
            return;
        }
        const int rc = std::snprintf(cmd, sizeof(cmd),
                      "iptables -w 5 -A %s -p tcp "
                      "--tcp-flags FIN,SYN,RST,ACK ACK "
                      "-d %s -j DROP 2>/dev/null",
                      kTesterStimulusChain, dut_ip);
        if (rc < 0 || rc >= static_cast<int>(sizeof(cmd))) return;
        if (std::system(cmd) == 0) {
            installed_ = true;
            dut_ip_.assign(dut_ip);
        } else {
            std::fprintf(stderr,
                         "tcp-pilot: TesterAutoAckDrop install failed "
                         "(continuing without ACK suppression)\n");
        }
    }

    ~TesterAutoAckDrop() {
        if (!installed_) return;
        char cmd[256];
        std::snprintf(cmd, sizeof(cmd),
                      "iptables -w 5 -D %s -p tcp "
                      "--tcp-flags FIN,SYN,RST,ACK ACK "
                      "-d %s -j DROP 2>/dev/null",
                      kTesterStimulusChain, dut_ip_.c_str());
        int rc = std::system(cmd);
        (void)rc;
    }

    TesterAutoAckDrop(const TesterAutoAckDrop &)            = delete;
    TesterAutoAckDrop &operator=(const TesterAutoAckDrop &) = delete;

    bool installed() const { return installed_; }

private:
    bool installed_ = false;
    std::string dut_ip_;
};

// Subset of the TCP header fields a stimulus-side capture snippet
// commonly needs. SEQ/ACK are the DUT-emitted values UNACCEPTABLE_03
// learns from the SYN+ACK to compute an "unacceptable ACK" inject;
// flags + ports surface so the caller can sanity-check the BPF
// match before relying on SEQ/ACK.
struct CapturedTcpHeader {
    std::uint32_t seq_num  = 0;
    std::uint32_t ack_num  = 0;
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    std::uint8_t  flags    = 0;
};

// Stimulus-side single-frame TCP capture. Opens a libpcap handle on
// `iface`, arms a BPF filter, and lets the caller block-pump for
// the next matching frame. Used by §4.8.6.3 UNACCEPTABLE_03 (and
// any case that needs to learn DUT-emitted SEQ/ACK before
// constructing a dependent raw-inject) — open the snippet BEFORE
// emitting the upstream stimulus, then `tryCapture` after, so the
// pcap kernel ring buffers the DUT segment regardless of how
// quickly it arrives.
//
// Independent of the harness's main pcap source (TestRunner's
// PcapSource) — the BPF filter and consumption are stimulus-private.
class TcpFrameSnippet {
public:
    TcpFrameSnippet(std::string_view iface, std::string_view bpf_filter)
        : handle_(nullptr) {
        char errbuf[PCAP_ERRBUF_SIZE] = {};
        // 100 ms libpcap read timeout matches `PcapSource::openLive`'s
        // budget — long enough to absorb scheduler jitter, short
        // enough that tryCapture can poll cleanly.
        handle_ = pcap_open_live(std::string(iface).c_str(),
                                  /*snaplen=*/65535,
                                  /*promisc=*/1,
                                  /*to_ms=*/100, errbuf);
        if (handle_ == nullptr) {
            std::fprintf(stderr,
                         "tcp-pilot: snippet pcap_open_live(%.*s) failed: %s\n",
                         static_cast<int>(iface.size()), iface.data(), errbuf);
            return;
        }
        pcap_setnonblock(handle_, 1, errbuf);
        bpf_program prog{};
        if (pcap_compile(handle_, &prog,
                          std::string(bpf_filter).c_str(),
                          /*optimize=*/1, PCAP_NETMASK_UNKNOWN) < 0) {
            std::fprintf(stderr,
                         "tcp-pilot: snippet pcap_compile(%.*s) failed: %s\n",
                         static_cast<int>(bpf_filter.size()),
                         bpf_filter.data(), pcap_geterr(handle_));
            pcap_close(handle_);
            handle_ = nullptr;
            return;
        }
        const int set_rc = pcap_setfilter(handle_, &prog);
        pcap_freecode(&prog);
        if (set_rc < 0) {
            std::fprintf(stderr,
                         "tcp-pilot: snippet pcap_setfilter failed: %s\n",
                         pcap_geterr(handle_));
            pcap_close(handle_);
            handle_ = nullptr;
        }
    }

    ~TcpFrameSnippet() {
        if (handle_ != nullptr) pcap_close(handle_);
    }

    TcpFrameSnippet(const TcpFrameSnippet &)            = delete;
    TcpFrameSnippet &operator=(const TcpFrameSnippet &) = delete;
    TcpFrameSnippet(TcpFrameSnippet &&other) noexcept : handle_(other.handle_) {
        other.handle_ = nullptr;
    }

    bool ok() const { return handle_ != nullptr; }

    // Factory: snippet matching the DUT-emitted SYN on
    // `dut_local_port` (the source port the active-OPEN flavor
    // tc8-dut binds to). Used by §4.8.6.3 UNACCEPTABLE_08 to learn
    // ISN_d before crafting the bad-ACK inject. The BPF mask
    // (`0x12 == 0x02`) selects SYN-only segments, excluding the
    // SYN+ACK any tester listener would emit.
    static TcpFrameSnippet forDutSyn(const ::tc8::TestConfig &cfg,
                                      std::string_view iface,
                                      std::uint16_t dut_local_port) {
        char dut_ip[INET_ADDRSTRLEN] = {};
        ::inet_ntop(AF_INET, &cfg.ipv4.dut_iface_ip, dut_ip, sizeof(dut_ip));
        char bpf[160];
        std::snprintf(bpf, sizeof(bpf),
                      "src host %s and tcp src port %u and "
                      "(tcp[13] & 0x12) == 0x02",
                      dut_ip, static_cast<unsigned>(dut_local_port));
        return TcpFrameSnippet(iface, bpf);
    }

    // Factory: snippet matching the DUT-emitted SYN+ACK whose
    // dst_port equals `tester_src_port` (the source port the
    // tester's raw-inject SYN used). Used by §4.8.6.3
    // UNACCEPTABLE_03 to learn ISN_d before crafting the bad-ACK
    // inject. The BPF mask (`0x12 == 0x12`) selects SYN+ACK
    // exactly, ruling out plain ACK retransmits or stray RST+ACK
    // frames that share the port quad.
    static TcpFrameSnippet forDutSynAck(const ::tc8::TestConfig &cfg,
                                         std::string_view iface,
                                         std::uint16_t tester_src_port) {
        char dut_ip[INET_ADDRSTRLEN] = {};
        ::inet_ntop(AF_INET, &cfg.ipv4.dut_iface_ip, dut_ip, sizeof(dut_ip));
        char bpf[160];
        std::snprintf(bpf, sizeof(bpf),
                      "src host %s and tcp dst port %u and "
                      "(tcp[13] & 0x12) == 0x12",
                      dut_ip, static_cast<unsigned>(tester_src_port));
        return TcpFrameSnippet(iface, bpf);
    }

    // Poll for the next BPF-matching frame up to `timeout`. Parses
    // the Ethernet (14 B) + IPv4 (variable IHL) + TCP header on hit
    // and returns the captured SEQ/ACK/flags/ports. Returns nullopt
    // on timeout, malformed frame (caplen too small for parse), or
    // handle init failure.
    std::optional<CapturedTcpHeader> tryCapture(std::chrono::milliseconds timeout) {
        if (handle_ == nullptr) return std::nullopt;
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            pcap_pkthdr *hdr = nullptr;
            const u_char *data = nullptr;
            const int rc = pcap_next_ex(handle_, &hdr, &data);
            if (rc == 1 && hdr != nullptr && data != nullptr) {
                if (hdr->caplen < 14 + 20 + 20) continue;
                // Ethernet → IPv4 → TCP. Assume Ethernet II (14 B
                // L2) — fine for veth. IHL is the low nibble of
                // byte 0 in the IPv4 header; multiply by 4 for
                // bytes.
                const std::uint8_t ip_ihl = (data[14] & 0x0F) * 4U;
                if (ip_ihl < 20U) continue;
                const std::size_t tcp_off = 14U + ip_ihl;
                if (hdr->caplen < tcp_off + 20U) continue;
                const std::uint8_t *tcp = data + tcp_off;
                CapturedTcpHeader h{};
                h.src_port = static_cast<std::uint16_t>(
                    (static_cast<std::uint16_t>(tcp[0]) << 8) | tcp[1]);
                h.dst_port = static_cast<std::uint16_t>(
                    (static_cast<std::uint16_t>(tcp[2]) << 8) | tcp[3]);
                h.seq_num =
                      (static_cast<std::uint32_t>(tcp[4])  << 24)
                    | (static_cast<std::uint32_t>(tcp[5])  << 16)
                    | (static_cast<std::uint32_t>(tcp[6])  <<  8)
                    |  static_cast<std::uint32_t>(tcp[7]);
                h.ack_num =
                      (static_cast<std::uint32_t>(tcp[8])  << 24)
                    | (static_cast<std::uint32_t>(tcp[9])  << 16)
                    | (static_cast<std::uint32_t>(tcp[10]) <<  8)
                    |  static_cast<std::uint32_t>(tcp[11]);
                h.flags = tcp[13];
                return h;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        return std::nullopt;
    }

private:
    pcap_t *handle_;
};

// Linux's TIME-WAIT timer is hardcoded as `TCP_TIMEWAIT_LEN = 60 * HZ`
// in net/ipv4/tcp.h — a runtime sysctl knob does not exist. The §4.8
// TC8 v3.0 spec parameter table (p291 glossary) defines `msl` as
// "Maximum segment lifetime used by DUT" and offers no short test
// value; the only path is to wait 2 * MSL + spec's 20 % margin for
// real. For the Linux DUT under test this is 60 s × 1.20 = 72 s.
//
// COUPLING NOTE: BASICS_11/12 SCXML files hardcode their
// `Listening_replay_rst` deadline to 78s (= 72 + 6 s observation
// margin). SCXML `<send delay="..."/>` accepts string literals
// only — there is no source-of-truth bridge between this constant
// and the SCXML attribute. Adjusting this constant requires a
// matched edit to both `tests/tcp_basics_11/tcp_basics_11.scxml`
// and `tests/tcp_basics_12/tcp_basics_12.scxml`.
inline constexpr auto kTimeWaitFullWait = std::chrono::seconds(72);

// Captured tester-side TCP sequence numbers at the moment the DUT
// transitioned into TIME-WAIT, exposed so callers can build raw-
// inject probes against the now-extinct kernel socket.
//
// `tester_seq_post_fin` — what the tester's snd_nxt becomes after
// the kernel emits its FIN (FIN consumes 1 sequence number on top of
// the post-handshake snd_nxt). Use this as `seq_num` for any segment
// the post-TIME-WAIT replay phase emits.
//
// `tester_ack_post_fin` — what the tester's rcv_nxt becomes after
// the DUT FIN was consumed (rcv_nxt advances by 1 over the byte the
// FIN occupies). Use this as `ack_num` for an "acceptable" ACK that
// acknowledges through the DUT FIN.
//
// Both values reflect the wire-level state immediately AFTER the
// FW2 → TIME-WAIT transition; the tester socket is closed before
// `driveTcpToTimeWaitFw2` returns, so subsequent kernel queries
// against the same fd would fail.
struct TcpTimeWaitInfo {
    bool          ok                  = false;
    std::uint32_t tester_seq_post_fin = 0;
    std::uint32_t tester_ack_post_fin = 0;
};

// Active-OPEN prelude. Drives DUT into ESTABLISHED via UT
// OpOpenTcpSocket(Active) against an auxiliary tester listener bound
// on `remote_port`, returning the listener (move-only RAII). Single
// call replaces the four-step prelude — listener bind, UT request,
// RPC settle, handshake settle — that BASICS_06+ and CHECKSUM_01..03
// otherwise repeat verbatim.
//
// What this helper deliberately does NOT do:
//   * Top-level kTcpUtBootWait. Compound shapes (BASICS_08, BASICS_10)
//     run the helper twice with distinct port quads, but only the
//     first phase needs the boot sync; the caller pays kTcpUtBootWait
//     once at the head of stimulus.
//   * acceptOne(). Some callers do not need the tester-side fd
//     (BASICS_06, BASICS_07) and forcing accept() in the helper would
//     consume the queue prematurely. Cases that need the tester fd
//     (CHECKSUM_01/02, BASICS_08 phase 2, BASICS_09, BASICS_10) call
//     `listener.acceptOne()` after the helper returns.
//
// The kTcpActiveHandshakeGrace inclusion is unconditional: BASICS_06
// observes only the SYN and does not strictly require ESTABLISHED,
// but the 50 ms cost is well inside its 5 s SCXML deadline and
// keeping the prelude shape uniform across all eight call sites
// removes a per-case decision point.
// `local_port` + `remote_port` are intentionally non-default — every
// caller must pick a unique 4-tuple so a TIME-WAIT / LAST_ACK residue
// from a sibling on the same worker netns cannot collide with the
// next case's bind. See `reference_active_open_port_quad_collision.md`
// for the BASICS_11 EADDRNOTAVAIL precedent. Per-case offsets live
// in the +200..+219 reservation block above (kTcpBasicsNNLocalOffset,
// kTcpChecksumNNLocalOffset, kTcpUnacceptableNNLocalOffset).
inline TesterTcpListener driveActiveOpenEstablished(
    const ::tc8::TestConfig &cfg,
    std::string_view iface,
    const std::array<std::uint8_t, 6> &dut_mac,
    std::uint8_t  open_req_id,
    std::uint16_t local_port,
    std::uint16_t remote_port) {
    TesterTcpListener listener(remote_port);
    sendOpenTcpSocketActiveRequest(
        cfg, iface, dut_mac,
        open_req_id, local_port,
        cfg.ipv4.tester_ip, remote_port);
    std::this_thread::sleep_for(kTcpUtRpcWait);
    std::this_thread::sleep_for(kTcpActiveHandshakeGrace);
    return listener;
}

// Result of `driveRawPassiveHandshake`. `dut_isn` is the DUT-emitted
// SYN+ACK seq_num parsed from the snippet capture — callers that need
// to drive the connection further (e.g. an in-window data probe after
// the handshake) compose tester ACK / data segments off this value.
// `ut_established` is the OpQueryTcpEstablished response byte (0xFF =
// not queried, 0x00 = not established, 0x01 = established).
struct RawPassiveHandshakeInfo {
    bool          ok               = false;
    std::uint32_t dut_isn          = 0;
    std::uint16_t tester_src_port  = 0;
    std::uint8_t  ut_established   = 0xFFU;
};

// Tester-driven 3-way handshake against a DUT-side passive listener,
// with full control over the tester's SYN options bytes. Used by §4.8
// .6.9 TCP_MSS_OPTIONS_01..03 — the spec procedure has the tester
// inject a hand-crafted SYN whose options region carries an MSS value
// of an illegal length (_01), an unimplemented option kind (_03), or
// NOP/EOL placeholders (_02), then asserts the DUT either ignores the
// malformed bytes (_02/_03 complete the handshake; _01 simply does
// not crash) or otherwise survives without disturbing the rest of
// the kernel's TCP stack.
//
// Mechanism:
//   1. UT OpOpenTcpSocket(passive, listen_port) — DUT enters LISTEN.
//   2. Open `TcpFrameSnippet::forDutSynAck` keyed on `tester_src_port`
//      so the snippet ring buffers the DUT's SYN+ACK before the
//      tester's third-leg ACK closes the listen window.
//   3. RAII `TesterAutoRstDrop` — Linux's tester kernel sees the
//      DUT-emitted SYN+ACK on a 4-tuple where it has no socket and
//      would otherwise emit an RST that would crash the embryonic
//      handshake; the iptables OUTPUT drop suppresses that.
//   4. Raw-inject SYN with `syn_options` bytes pre-encoded per
//      RFC 793 §3.1 (caller is responsible for option layout —
//      `buildTcpSegment` pads to a 4-byte boundary and recomputes
//      Data Offset). seq=kTesterInitialSeq.
//   5. `tryCapture` the DUT SYN+ACK (timeout `capture_timeout`).
//      Returns `ok=false` on timeout — the case's SCXML still has the
//      SYN+ACK in the harness pcap (different libpcap handle), so
//      cases that rely solely on the SYN+ACK pass guard can ignore
//      the helper's `ok` and consult `captured.flags` instead.
//   6. Raw-inject ACK with seq=kTesterInitialSeq+1, ack=dut_isn+1.
//      DUT TCB transitions SYN-RCVD → ESTABLISHED on receipt.
//   7. 50 ms settle (mirrors BASICS_02's wait between handshake and
//      query so the kernel's accept queue drains and accept() yields
//      a non-zero established flag inside the UT server).
//   8. Optional UT OpQueryTcpEstablished — only fired when
//      `query_req_id != 0`. Result lands in `info.ut_established`.
//
// Caller is expected to invoke `sendCloseTcpSocketRequest` after the
// helper returns to tear the DUT-side fd down. The `TesterAutoRstDrop`
// scope ends when the helper returns, restoring normal RST handling
// before any post-helper raw-inject probes that need the tester
// kernel to reflect RST behaviour.
//
// PARAMETER-COUNT THRESHOLD (audit 2026-04-27 late, SEQUENCE session):
// the signature now carries 9 parameters (4 required + 5 with
// defaults; `tester_isn` was the 9th, added for §4.8.6.17). The next
// addition MUST refactor the trailing default-bearing params into a
// `RawPassiveHandshakeOpts` struct to keep call sites readable. The
// existing 10 call sites use positional + `/*name=*/literal` comments
// to document binding intent — already at the limit of what positional
// args remain readable for. Do not add a 10th parameter inline.
inline RawPassiveHandshakeInfo driveRawPassiveHandshake(
    const ::tc8::TestConfig &cfg,
    std::string_view iface,
    const std::array<std::uint8_t, 6> &dut_mac,
    std::uint16_t listen_port,
    std::vector<std::uint8_t> syn_options,
    std::uint16_t tester_src_port = kBasicsTesterPort,
    std::uint8_t  open_req_id     = 1,
    std::uint8_t  query_req_id    = 0,
    std::uint8_t  socket_id       = 1,
    std::chrono::milliseconds capture_timeout =
        std::chrono::milliseconds(2000),
    std::uint32_t tester_isn      = kTesterInitialSeq) {
    RawPassiveHandshakeInfo info{};
    info.tester_src_port = tester_src_port;

    sendOpenTcpSocketPassiveRequest(cfg, iface, dut_mac,
                                     open_req_id, listen_port);
    std::this_thread::sleep_for(kTcpUtRpcWait);

    auto snippet = TcpFrameSnippet::forDutSynAck(cfg, iface, tester_src_port);
    if (!snippet.ok()) return info;

    TesterAutoRstDrop rst_drop(cfg);

    ::tc8::stimulus::TcpSegmentSpec syn_spec{};
    syn_spec.src_port = tester_src_port;
    syn_spec.dst_port = listen_port;
    syn_spec.seq_num  = tester_isn;
    syn_spec.flags    = ::tc8::stimulus::kTcpFlagSyn;
    syn_spec.options  = std::move(syn_options);
    emitTcpFrame(cfg, iface, dut_mac, syn_spec);

    const auto syn_ack = snippet.tryCapture(capture_timeout);
    if (!syn_ack) return info;
    info.dut_isn = syn_ack->seq_num;

    // SYN consumes 1 sequence number per RFC 793 §3.3 — the tester's
    // post-SYN snd_nxt is `tester_isn + 1U`. uint32 wraparound is the
    // intended semantics for §4.8.6.17 SEQUENCE_04 (tester_isn ==
    // 0xFFFFFFFF ⇒ post-SYN snd_nxt == 0).
    ::tc8::stimulus::TcpSegmentSpec ack_spec{};
    ack_spec.src_port = tester_src_port;
    ack_spec.dst_port = listen_port;
    ack_spec.seq_num  = tester_isn + 1U;
    ack_spec.ack_num  = info.dut_isn + 1U;
    ack_spec.flags    = ::tc8::stimulus::kTcpFlagAck;
    emitTcpFrame(cfg, iface, dut_mac, ack_spec);

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    if (query_req_id != 0U) {
        info.ut_established = queryTcpEstablishedSync(cfg, query_req_id, socket_id);
    }

    info.ok = true;
    return info;
}

// Drive DUT into TIME-WAIT via the FIN-WAIT-2 path:
//   1. Active-OPEN handshake → ESTABLISHED (driveActiveOpenEstablished).
//   2. Tester accept() pulls the connected fd off the listener queue.
//   3. UT OpCloseTcpSocket → DUT FIN. Tester kernel auto-ACKs the FIN
//      (no iptables suppression), advancing DUT's TCB through
//      FIN-WAIT-1 → FIN-WAIT-2 in a single auto-ACK pass.
//   4. queryTcpSeqRange snapshots tester snd_nxt / rcv_nxt at the
//      moment DUT FIN has been consumed but tester FIN has not yet
//      been sent. The captured pair is used by callers that raw-
//      inject post-TIME-WAIT probes (UNACCEPTABLE_13 / FLAGS_INVALID
//      _14 OTW SEQ, BASICS_11/13 replay FIN).
//   5. ::shutdown(tester_fd, SHUT_WR) → tester FIN+ACK. DUT replies
//      pure ACK and transitions FIN-WAIT-2 → TIME-WAIT.
//   6. ::close(tester_fd) — tester socket has already completed its
//      LAST-ACK / CLOSED transition by step 5, so close() is a no-op
//      teardown of the fd. After return, the tester kernel holds no
//      socket on the (local_port, remote_port) quad — subsequent
//      raw-inject from this 4-tuple goes through cleanly.
//
// The 200 ms settle wait between UT close and queryTcpSeqRange
// matches UNACCEPTABLE_10's empirically-validated grace; the second
// 200 ms wait between shutdown(WR) and ::close gives the DUT ACK
// time to land at tester before tester closes (preventing the rare
// race where ::close races the ACK reception and the kernel emits
// a stray RST instead of completing LAST-ACK).
//
// Returns `ok=false` on any local syscall failure; the wire-level
// transitions are observed by SCXML, not asserted here.
// `local_port` + `remote_port` are intentionally non-default — see
// `driveActiveOpenEstablished` block comment for the per-case
// 4-tuple isolation rationale.
inline TcpTimeWaitInfo driveTcpToTimeWaitFw2(
    const ::tc8::TestConfig &cfg,
    std::string_view iface,
    const std::array<std::uint8_t, 6> &dut_mac,
    std::uint8_t  open_req_id,
    std::uint8_t  close_req_id,
    std::uint8_t  socket_id,
    std::uint16_t local_port,
    std::uint16_t remote_port) {
    auto listener = driveActiveOpenEstablished(
        cfg, iface, dut_mac, open_req_id, local_port, remote_port);
    const int tester_fd = listener.acceptOne();
    if (tester_fd < 0) return {};

    sendCloseTcpSocketRequest(cfg, iface, dut_mac, close_req_id, socket_id);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    const auto seq_pre_fin = queryTcpSeqRange(tester_fd);
    if (!seq_pre_fin.has_value()) {
        ::close(tester_fd);
        return {};
    }

    ::shutdown(tester_fd, SHUT_WR);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    ::close(tester_fd);

    TcpTimeWaitInfo info{};
    info.ok                  = true;
    // Pre-FIN snd_nxt = ISN_t + 1 (post-handshake, no data sent).
    // After kernel emits FIN at shutdown(WR), snd_nxt advances by 1
    // (FIN consumes 1 sequence number) → ISN_t + 2.
    info.tester_seq_post_fin = seq_pre_fin->snd_nxt + 1U;
    // rcv_nxt at query time already reflects the consumed DUT FIN
    // (= ISN_d + 2). No further advance from the tester FIN.
    info.tester_ack_post_fin = seq_pre_fin->rcv_nxt;
    return info;
}

// Drive DUT into TIME-WAIT via the CLOSING path:
//   1. UT OpCloseTcpSocket → DUT FIN. TesterAutoAckDrop installed
//      for the duration of this call suppresses the tester kernel's
//      pure-ACK auto-reply, so DUT stays in FIN-WAIT-1 instead of
//      transitioning into FIN-WAIT-2.
//   2. queryTcpSeqRange snapshots tester snd_nxt / rcv_nxt with
//      DUT FIN consumed (rcv_nxt = ISN_d + 2) but tester FIN not
//      yet sent (snd_nxt = ISN_t + 1).
//   3. Raw-inject tester FIN+ACK with seq = snd_nxt (ISN_t + 1) and
//      ack = rcv_nxt - 1 (ISN_d + 1). The ack is RFC 793 acceptable
//      (in [snd.una, snd.nxt]) but does NOT acknowledge the DUT FIN
//      — DUT in FIN-WAIT-1 receives a non-acking FIN and per RFC
//      793 RFC 793 §3.9 enters CLOSING. DUT replies pure ACK (which the
//      ack_drop iptables rule does NOT block — it only matches
//      pure ACKs egressing from the tester kernel, not DUT egress).
//   4. Raw-inject tester ACK with seq = snd_nxt + 1 (ISN_t + 2,
//      post-FIN) and ack = rcv_nxt (ISN_d + 2, acknowledging DUT
//      FIN). DUT transitions CLOSING → TIME-WAIT silently.
//   5. TCP_REPAIR + ::close on tester_fd silently disposes the
//      kernel socket — no FIN goes out (TCP_REPAIR mode suppresses
//      the close-time FIN per the documented kernel semantics).
//      The (local_port, remote_port) 4-tuple is now free of any
//      tester-side kernel state, so subsequent post-prelude raw-
//      inject (the replay-FIN phase) does not race kernel auto-
//      replies.
//
// Returns `ok=false` if any local syscall fails. The caller owns
// `tester_fd` ON ENTRY and the helper consumes it; on either
// success or failure the fd is closed before return (TCP_REPAIR
// path on success, plain ::close on failure).
//
// The TesterAutoAckDrop is scoped inside this helper — its
// destructor removes the iptables rule before return. After return
// the kernel has no socket on the 4-tuple, so the iptables rule is
// no longer load-bearing; releasing it eliminates cross-case state
// pollution.
// `local_port` + `remote_port` are intentionally non-default — see
// `driveActiveOpenEstablished` block comment for the per-case
// 4-tuple isolation rationale.
inline TcpTimeWaitInfo driveCloseToTimeWaitClosing(
    const ::tc8::TestConfig &cfg,
    std::string_view iface,
    const std::array<std::uint8_t, 6> &dut_mac,
    int           tester_fd,
    std::uint8_t  close_req_id,
    std::uint8_t  socket_id,
    std::uint16_t local_port,
    std::uint16_t remote_port) {
    auto silent_close = [tester_fd]() {
        if (tester_fd < 0) return;
        int repair_on = 1;
        ::setsockopt(tester_fd, IPPROTO_TCP, TCP_REPAIR,
                     &repair_on, sizeof(repair_on));
        ::close(tester_fd);
    };

    if (tester_fd < 0) return {};

    TesterAutoAckDrop ack_drop(cfg);
    sendCloseTcpSocketRequest(cfg, iface, dut_mac, close_req_id, socket_id);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    const auto seq = queryTcpSeqRange(tester_fd);
    if (!seq.has_value()) {
        ::close(tester_fd);
        return {};
    }

    // Step 3 — tester FIN+ACK that does NOT acknowledge DUT FIN.
    {
        ::tc8::stimulus::TcpSegmentSpec fin_seg{};
        fin_seg.src_port = remote_port;
        fin_seg.dst_port = local_port;
        fin_seg.seq_num  = seq->snd_nxt;
        // ack = rcv_nxt - 1 → "acceptable" ACK (in snd_una..snd_nxt
        // window from DUT's perspective) but does NOT ack DUT FIN.
        fin_seg.ack_num  = seq->rcv_nxt - 1U;
        fin_seg.flags    = ::tc8::stimulus::kTcpFlagFin
                         | ::tc8::stimulus::kTcpFlagAck;
        emitTcpFrame(cfg, iface, dut_mac, fin_seg,
                     /*initial_wait=*/std::chrono::milliseconds(0));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Step 4 — tester ACK that DOES acknowledge DUT FIN.
    {
        ::tc8::stimulus::TcpSegmentSpec ack_seg{};
        ack_seg.src_port = remote_port;
        ack_seg.dst_port = local_port;
        ack_seg.seq_num  = seq->snd_nxt + 1U;
        ack_seg.ack_num  = seq->rcv_nxt;
        ack_seg.flags    = ::tc8::stimulus::kTcpFlagAck;
        emitTcpFrame(cfg, iface, dut_mac, ack_seg,
                     /*initial_wait=*/std::chrono::milliseconds(0));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    silent_close();

    TcpTimeWaitInfo info{};
    info.ok                  = true;
    info.tester_seq_post_fin = seq->snd_nxt + 1U;
    info.tester_ack_post_fin = seq->rcv_nxt;
    return info;
}

// Drive DUT into CLOSING (the "FIN-WAIT-1 + tester FIN crossed
// before our ACK" transition) WITHOUT advancing further to
// TIME-WAIT. Identical to driveCloseToTimeWaitClosing through
// step 3 (raw-inject FIN+ACK with non-acking ack) — the
// follow-on ACK that would acknowledge DUT FIN and drive
// CLOSING → TIME-WAIT is omitted. Tester fd is also left open
// because the caller needs the (live, kernel-tracked) socket to
// stay non-conflicting with subsequent raw-inject probes inside
// the still-active TesterAutoAckDrop scope; the caller must
// silently dispose the fd via TCP_REPAIR + close once the probe
// phase completes.
//
// Caller responsibilities (UNACCEPTABLE_11 / FLAGS_INVALID_12):
//   1. Install TesterAutoAckDrop in caller scope BEFORE invoking
//      this helper — the helper relies on the kernel pure-ACK
//      auto-reply being suppressed.
//   2. Use returned info.tester_seq_post_fin / .tester_ack_post_fin
//      as the seq/ack BASE for any subsequent raw-inject probe
//      (offset OTW SEQ via kOutOfWindowSeqOffset, etc.).
//   3. After the probe phase, TCP_REPAIR-silently close `tester_fd`
//      to free kernel state without emitting FIN+ACK. The
//      TesterAutoAckDrop scope can then end.
//
// Returns `ok=false` on local syscall failure; tester_fd is closed
// with plain ::close on the queryTcpSeqRange-failure path so the
// helper does not leak the descriptor.
// `local_port` + `remote_port` are intentionally non-default — see
// `driveActiveOpenEstablished` block comment for the per-case
// 4-tuple isolation rationale.
inline TcpTimeWaitInfo driveCloseToClosing(
    const ::tc8::TestConfig &cfg,
    std::string_view iface,
    const std::array<std::uint8_t, 6> &dut_mac,
    int           tester_fd,
    std::uint8_t  close_req_id,
    std::uint8_t  socket_id,
    std::uint16_t local_port,
    std::uint16_t remote_port) {
    if (tester_fd < 0) return {};

    sendCloseTcpSocketRequest(cfg, iface, dut_mac, close_req_id, socket_id);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    const auto seq = queryTcpSeqRange(tester_fd);
    if (!seq.has_value()) {
        ::close(tester_fd);
        return {};
    }

    {
        ::tc8::stimulus::TcpSegmentSpec fin_seg{};
        fin_seg.src_port = remote_port;
        fin_seg.dst_port = local_port;
        fin_seg.seq_num  = seq->snd_nxt;
        fin_seg.ack_num  = seq->rcv_nxt - 1U;  // Does NOT ack DUT FIN.
        fin_seg.flags    = ::tc8::stimulus::kTcpFlagFin
                         | ::tc8::stimulus::kTcpFlagAck;
        emitTcpFrame(cfg, iface, dut_mac, fin_seg,
                     /*initial_wait=*/std::chrono::milliseconds(0));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    TcpTimeWaitInfo info{};
    info.ok                  = true;
    info.tester_seq_post_fin = seq->snd_nxt + 1U;
    info.tester_ack_post_fin = seq->rcv_nxt;
    return info;
}

// TCP_REPAIR-silent dispose of a tester socket: setting
// TCP_REPAIR=1 before close() makes the kernel deallocate the
// socket without emitting FIN per the documented semantics. Used
// by CLOSING-state stimulus paths (UNACCEPTABLE_11 / FLAGS_INVALID
// _12) to free the (local_port, remote_port) 4-tuple after the
// probe phase without disturbing DUT state with a stray tester
// FIN. Idempotent on tester_fd < 0.
inline void silentlyCloseTesterFd(int tester_fd) {
    if (tester_fd < 0) return;
    int repair_on = 1;
    ::setsockopt(tester_fd, IPPROTO_TCP, TCP_REPAIR,
                 &repair_on, sizeof(repair_on));
    ::close(tester_fd);
}

}  // namespace tc8::sce::tcp
