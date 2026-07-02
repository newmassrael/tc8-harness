#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
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
#include "sce_integration/tester_stimulus_chain.h"  // kTesterStimulusChain / ensureTesterStimulusChain (SSOT).
#include "stimulus/endpoint.h"                       // Endpoint — per-connection 4-tuple.
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

// Inter-SEND gap for seam-driven Nagle tests that hold a small segment while a
// prior one is unacked (tester ACKs suppressed). The seam's synchronous active
// OPEN returns the instant the connection is established, removing the
// ~kTcpUtRpcWait slack the opcode-direct open carried; without it the second
// SEND can land exactly on the first segment's retransmission timeout (Linux
// TCP_RTO_MIN ~200 ms), and a small segment offered at the RTO boundary escapes
// Nagle's hold. Spacing the SENDs past TCP_RTO_MIN guarantees the next SEND
// enqueues after the first segment's first retransmit, keeping the Nagle hold
// deterministic on both backends. 350 ms = TCP_RTO_MIN (~200 ms) + jitter
// margin. SSOT for NAGLE_02, NAGLE_03, FLAGS_PROCESSING_10.
inline constexpr auto kTcpSeamInterSendRtoClearGap = std::chrono::milliseconds(350);

// Seed SEQ value the tester uses on its SYN / flag-stimulus segments.
// Chosen non-zero so BASICS_04's pass criterion ("DUT's RST SEQ == 0")
// is structurally distinct from the tester's SEQ — a bug where the
// pipeline mirrors the stimulus seq back into Captured would false-fail
// the SEQ-zero guard rather than silently masquerade as pass.
inline constexpr std::uint32_t kTesterInitialSeq = 0x10203040U;

// §4.8.6.1 TCP_BASICS_05 tester-chosen ACK literals: the DUT's RFC 793 §3.9 RST to an
// ACK-bearing closed-port segment carries SEQ <- incoming.ACK, so each phase's guard
// pins to its literal. Distinct per phase (and from kTesterInitialSeq) so a stuck-at DUT
// that mirrors one phase's SEQ false-fails the other rather than masquerading. SSOT for
// the positive's stimulus, its scxml guards, and the BASICS_05_NEG/_NEG2 self-validation
// siblings (which must inject the same ACK the guard checks).
inline constexpr std::uint32_t kTesterPilotAckPhaseSynAck = 0xC0FFEE00U;
inline constexpr std::uint32_t kTesterPilotAckPhaseAck    = 0xDEADBEEFU;

// RFC 1122 §4.2.2.6 default Maximum Segment Size. Tester-side SSOT for the §4.8.6.9
// MSS_OPTIONS_12 guards (positive asserts mss != 536; the _NEG forces mss == 536). The
// lwIP fixture carries its own copy of this wire value (the DUT and tester are separate
// compilation domains; the 16-bit wire field is the only shared contract).
inline constexpr std::uint16_t kRfcDefaultMss = 536U;

// §4.8 active-OPEN port-quad offset constants — generated from the single
// source of truth tcp_active_open_offsets.def (X-macro idiom, see
// verdict_taxonomy.def). Editing an offset = editing one .def line, which
// updates BOTH the named constant here AND kActiveOpenOffsetRegistry below.
#define TC8_TCP_OFFSET(name, value)        inline constexpr std::uint16_t name = value##U;
#define TC8_TCP_OFFSET_SPAN5(name, base)   inline constexpr std::uint16_t name = base##U;
#include "sce_integration/tcp_active_open_offsets.def"
#undef TC8_TCP_OFFSET
#undef TC8_TCP_OFFSET_SPAN5


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

// §4.8.6.16 TCP_HEADER_04 raw-inject "wrong" tester SOURCE port (PORT2). The case drives an
// EST connection on (kBasicsActiveLocalPort + kTcpHeader04LocalOffset, kBasicsActiveRemotePort
// + kTcpHeader04LocalOffset), then raw-injects an in-window data segment FROM this source port
// — deliberately the REMOTE base + 132, ~100 above the §4.8.6 HEADER cluster's +30..+38
// active-OPEN block, so it matches no connection and a conformant DUT drops it per the
// RFC 793 §3.1 / §3.9 4-tuple demux. The +132 numerically aliases kTcpNagle02LocalOffset = 132
// on the LOCAL axis only (different base, no actual port collision). One SSOT definition, shared
// by the positive and its _NEG (which only arms the source-port-blind fault flavor) — a different
// axis from the shared 4-tuple offset in tcp_active_open_offsets.def, so it lives here, not there.
inline constexpr std::uint16_t kTcpHeader04WrongRemotePort = kBasicsActiveRemotePort + 132U;

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


// §4.8.6.15 CONNECTION_ESTAB_07 — passive close path. Same shape
// as BASICS_03 but on a private listen port so cluster-wide cases
// running in parallel never collide on the BASICS_03 listen.
inline constexpr std::uint16_t kTcpConnEstab07ListenPort     = 13179U;


// §4.8.6.2 CHECKSUM_02 / §4.8.6.7 FLAGS_PROCESSING_09 lwIP _NEG active-OPEN
// offsets are defined in the consolidated 0..97 registry block below. They were
// moved off 60..63 to 42..45 to clear the FLAGS_PROCESSING_02 positive, which
// binds 60..63 — a collision the prior hand-audit missed because that positive
// used bare literals invisible to its "registered positives" check.


// kActiveOpenOffsetRegistry — built from the SAME tcp_active_open_offsets.def,
// so the uniqueness check covers exactly the declared set (no hand-synced
// duplicate). A SPAN5 contributes its 5-wide base+0..base+4 expansion.
#define TC8_TCP_OFFSET(name, value)        name,
#define TC8_TCP_OFFSET_SPAN5(name, base)                                 \
    static_cast<std::uint16_t>(name + 0U), static_cast<std::uint16_t>(name + 1U), \
    static_cast<std::uint16_t>(name + 2U), static_cast<std::uint16_t>(name + 3U), \
    static_cast<std::uint16_t>(name + 4U),
inline constexpr std::uint16_t kActiveOpenOffsetRegistry[] = {
#include "sce_integration/tcp_active_open_offsets.def"
};
#undef TC8_TCP_OFFSET
#undef TC8_TCP_OFFSET_SPAN5

constexpr bool offsetRegistryUnique() {
    constexpr std::size_t n =
        sizeof(kActiveOpenOffsetRegistry) / sizeof(kActiveOpenOffsetRegistry[0]);
    for (std::size_t i = 0; i < n; ++i)
        for (std::size_t j = i + 1U; j < n; ++j)
            if (kActiveOpenOffsetRegistry[i] == kActiveOpenOffsetRegistry[j])
                return false;
    return true;
}
static_assert(offsetRegistryUnique(),
              "TC8 §4.8 active-OPEN port-quad offsets must be globally unique; "
              "see tcp_active_open_offsets.def");

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

// Grace window between the active-OPEN return and the moment the
// tester-side socket is ESTABLISHED. Linux completes the 3-way
// handshake on a same-host netns in single-digit milliseconds; 50 ms
// is the conservative ceiling across observed jitter on busy parallel
// workers. Used by `driveSeamActiveOpen` so callers do not duplicate
// the magic-number sleep at every active-open prelude.
inline constexpr auto kTcpActiveHandshakeGrace = std::chrono::milliseconds(50);

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
// Encode a seam state-probe result (`ITcpStateProbe::isEstablished`) into the
// `ut_established` byte the SCXML guards read — the single source of truth for
// the tristate contract the SCXML established-guards consume:
//   0x01 — established,
//   0x00 — not established,
//   0xFF — query failed / probe returned nullopt (a hard-failure path, same
//          class as "no SYN+ACK within listen window").
// Pass std::nullopt when the open itself failed (no socket to probe) so callers
// collapse the open-failed branch into a single expression.
inline std::uint8_t utEstablishedByte(std::optional<bool> est) {
    return static_cast<std::uint8_t>(
        !est.has_value() ? 0xFFU : (*est ? 0x01U : 0x00U));
}

// Kernel-side TCP_INFO probing for the §4.8.6.11 RETRANSMISSION_TO
// cluster now goes through the Tier-2 seam: `IDutControl::tcpStateProbe()
// ->queryInfo()` returns a `DutTcpInfo` snapshot (see
// sce_integration/dut_socket_control.h and dut_control.h). The former
// direct `queryTcpInfoSync` / `TcpInfoSnapshot` helpers were retired once
// every cluster case (_03/_04/_05/_06/_08/_09) moved onto the seam.

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
    // Negotiated effective send MSS (Linux mss_cache) — the DUT's
    // on-wire data-segment size in this symmetric veth setup. A
    // timestamp-enabled peer (lwIP) shaves it to 1448 B; the
    // timestamp-disabled Linux reference DUT leaves it at 1460 B.
    // Cases that stride their seq expectations by the segment size
    // (PROBING_WINDOWS_03) read this instead of assuming a fixed MSS.
    // 0 if the query failed (caller falls back to a fixed default).
    std::uint16_t mss = 0;
};

inline std::optional<TcpSeqRange> queryTcpSeqRange(int fd) {
    if (fd < 0) return std::nullopt;

    // Read TCP_MAXSEG before entering TCP_REPAIR so it reflects the
    // live connection's effective send MSS.
    int maxseg_val = 0;
    {
        socklen_t mlen = sizeof(maxseg_val);
        (void)::getsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &maxseg_val, &mlen);
    }

    int repair_on = 1;
    if (::setsockopt(fd, IPPROTO_TCP, TCP_REPAIR, &repair_on, sizeof(repair_on)) < 0) {
        return std::nullopt;
    }

    TcpSeqRange r{};
    bool ok = true;
    if (maxseg_val > 0) r.mss = static_cast<std::uint16_t>(maxseg_val);

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

// The tester suppression chain (kTesterStimulusChain) and its create-and-jump
// helper (ensureTesterStimulusChain) are the SSOT in sce_integration/
// tester_stimulus_chain.h, shared by the OUTBOUND scopes below and the INBOUND
// TesterInboundDropScope, so the chain name has one home.

// RAII: DROP the DUT's inbound TCP segments on ONE connection (dut -> tester) for
// the scope's lifetime, so the tester kernel stops ACKing and the DUT's reliable
// send is intended to stall into half-open detection (the connection-lost teardown
// for a held reliable-subscribe connection). Installs into kTesterStimulusChain via
// the INPUT hook. Same non-fatal / RAII / `-w 5` discipline as TesterAutoRstDrop;
// the per-connection 4-tuple match keeps its rule from matching the outbound-RST
// rules that share the chain (those key on `-d DUT`, this on `-s DUT`).
class TesterInboundDropScope {
public:
    TesterInboundDropScope(const ::tc8::stimulus::Endpoint &dut,
                           const ::tc8::stimulus::Endpoint &tester) {
        char dut_ip[INET_ADDRSTRLEN] = {};
        char tester_ip[INET_ADDRSTRLEN] = {};
        if (::inet_ntop(AF_INET, &dut.ipv4_be, dut_ip, sizeof(dut_ip)) == nullptr ||
            ::inet_ntop(AF_INET, &tester.ipv4_be, tester_ip, sizeof(tester_ip)) == nullptr) {
            return;
        }
        if (!ensureTesterStimulusChain("INPUT")) {
            std::fprintf(stderr,
                         "tcp-pilot: TesterInboundDropScope chain setup failed "
                         "(continuing without the drop filter)\n");
            return;
        }
        const int rc = std::snprintf(match_, sizeof(match_),
                      "-p tcp -s %s --sport %u -d %s --dport %u -j DROP",
                      dut_ip, dut.port, tester_ip, tester.port);
        if (rc < 0 || rc >= static_cast<int>(sizeof(match_))) {
            return;
        }
        char cmd[320];
        std::snprintf(cmd, sizeof(cmd), "iptables -w 5 -A %s %s 2>/dev/null",
                      kTesterStimulusChain, match_);
        if (std::system(cmd) == 0) {
            installed_ = true;
        } else {
            std::fprintf(stderr,
                         "tcp-pilot: TesterInboundDropScope install failed "
                         "(continuing without the drop filter)\n");
        }
    }

    ~TesterInboundDropScope() {
        if (!installed_) return;
        char cmd[320];
        std::snprintf(cmd, sizeof(cmd), "iptables -w 5 -D %s %s 2>/dev/null",
                      kTesterStimulusChain, match_);
        const int rc = std::system(cmd);
        (void)rc;
    }

    TesterInboundDropScope(const TesterInboundDropScope &)            = delete;
    TesterInboundDropScope &operator=(const TesterInboundDropScope &) = delete;

    bool installed() const { return installed_; }

private:
    bool installed_ = false;
    char match_[256] = {};
};

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
// FW2 → TIME-WAIT transition; the tester socket is closed inside the
// `finishFw2ToTimeWait` core, so subsequent kernel queries
// against the same fd would fail.
struct TcpTimeWaitInfo {
    bool          ok                  = false;
    std::uint32_t tester_seq_post_fin = 0;
    std::uint32_t tester_ack_post_fin = 0;
};

// Backend-agnostic raw 3-way handshake against a DUT already in LISTEN: the SSOT
// for the tester-side wire choreography that the seam `driveSeamRawPassiveAccept`
// (cases/_tcp_seam_passive_open.h) composes — kept a named function so the seq
// arithmetic lives in exactly one place, separate from the verb's seam
// LISTEN+ACCEPT orchestration.
// Open the SYN+ACK snippet, suppress the tester-kernel RST (the DUT SYN+ACK lands
// on an unbound tester port), raw-inject the tester SYN with caller-controlled
// options bytes, capture the DUT SYN+ACK, raw-inject the acceptable third-leg
// ACK, and settle so the kernel's accept queue drains.
//
// Returns the DUT ISN (SYN+ACK seq_num) or nullopt if the snippet could not open
// or the DUT SYN+ACK never arrived. `tester_isn` lets the §4.8.6.17 SEQUENCE cases
// pin the tester's SYN seq (uint32 wraparound is the intended SEQUENCE_04
// semantics: tester_isn == 0xFFFFFFFF ⇒ post-SYN snd_nxt == 0). The
// TesterAutoRstDrop is scoped to the handshake it protects; a post-handshake UT /
// state query needs no RST suppression (the connection is ESTABLISHED and idle).
inline std::optional<std::uint32_t> rawPassiveThreeWayHandshake(
    const ::tc8::TestConfig &cfg, std::string_view iface,
    std::uint16_t listen_port, std::vector<std::uint8_t> syn_options,
    std::uint16_t tester_src_port, std::uint32_t tester_isn,
    std::chrono::milliseconds capture_timeout) {
    auto snippet = TcpFrameSnippet::forDutSynAck(cfg, iface, tester_src_port);
    if (!snippet.ok()) return std::nullopt;

    TesterAutoRstDrop rst_drop(cfg);

    ::tc8::stimulus::TcpSegmentSpec syn_spec{};
    syn_spec.src_port = tester_src_port;
    syn_spec.dst_port = listen_port;
    syn_spec.seq_num  = tester_isn;
    syn_spec.flags    = ::tc8::stimulus::kTcpFlagSyn;
    syn_spec.options  = std::move(syn_options);
    emitTcpFrame(cfg, iface, cfg.dut.mac, syn_spec);

    const auto syn_ack = snippet.tryCapture(capture_timeout);
    if (!syn_ack) return std::nullopt;

    // SYN consumes 1 sequence number per RFC 793 §3.3 — the tester's post-SYN
    // snd_nxt is tester_isn + 1U; ack the DUT ISN + 1 (acceptable third leg).
    ::tc8::stimulus::TcpSegmentSpec ack_spec{};
    ack_spec.src_port = tester_src_port;
    ack_spec.dst_port = listen_port;
    ack_spec.seq_num  = tester_isn + 1U;
    ack_spec.ack_num  = syn_ack->seq_num + 1U;
    ack_spec.flags    = ::tc8::stimulus::kTcpFlagAck;
    emitTcpFrame(cfg, iface, cfg.dut.mac, ack_spec);

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    return syn_ack->seq_num;
}

// ---- Backend-agnostic TIME-WAIT prelude cores ----------------------------
// The tester-side choreography that drives the DUT into TIME-WAIT lives here as
// the single source of truth, parameterised by a `dut_close` callback — the ONLY
// operation that varies by DUT-control backend (opcode UT close vs the Tier-2
// seam's closeTcp). The opcode wrappers below and the seam wrappers in
// cases/_tcp_seam_time_wait_prelude.h bind that callback; neither re-implements
// the wire mechanics. `dut_close` (a std::function) carries no dut_control.h
// dependency, so this file stays free of the concrete backend includes the 113
// sharing TUs reject.

// Raw-inject one tester FIN+ACK segment. `ack_num` = rcv_nxt-1 makes it NOT
// acknowledge the DUT FIN (RFC 793 §3.9 acceptable). Shared step of the
// CLOSING-path preludes.
inline void injectTesterFinAck(const ::tc8::TestConfig &cfg,
                               std::string_view iface,
                               const std::array<std::uint8_t, 6> &dut_mac,
                               std::uint16_t local_port,
                               std::uint16_t remote_port,
                               std::uint32_t seq_num,
                               std::uint32_t ack_num) {
    ::tc8::stimulus::TcpSegmentSpec fin_seg{};
    fin_seg.src_port = remote_port;
    fin_seg.dst_port = local_port;
    fin_seg.seq_num  = seq_num;
    fin_seg.ack_num  = ack_num;
    fin_seg.flags    = ::tc8::stimulus::kTcpFlagFin | ::tc8::stimulus::kTcpFlagAck;
    emitTcpFrame(cfg, iface, dut_mac, fin_seg,
                 /*initial_wait=*/std::chrono::milliseconds(0));
}

// FIN-WAIT-2 path core: given an accepted tester_fd and a way to close the DUT
// socket, drive DUT ESTABLISHED → FIN-WAIT-1 → FIN-WAIT-2 → TIME-WAIT.
//   1. dut_close() → DUT FIN. Tester kernel auto-ACKs (no suppression),
//      advancing the DUT TCB FIN-WAIT-1 → FIN-WAIT-2 in one pass.
//   2. queryTcpSeqRange snapshots tester snd_nxt / rcv_nxt with the DUT FIN
//      consumed but the tester FIN not yet sent.
//   3. ::shutdown(WR) → tester FIN+ACK; DUT replies pure ACK and moves
//      FIN-WAIT-2 → TIME-WAIT.
// The 200 ms settle after dut_close matches UNACCEPTABLE_10's validated grace;
// the second 200 ms before ::close lets the DUT ACK land first (avoiding a
// close()/ACK race RST). Consumes tester_fd (closed on every path). ok=false on
// tester_fd<0 or a failed seq snapshot. The returned seq/ack base feeds callers
// that raw-inject post-TIME-WAIT probes (UNACCEPTABLE_13, FLAGS_INVALID_14 OTW
// SEQ, BASICS_11/13 replay FIN).
inline TcpTimeWaitInfo finishFw2ToTimeWait(int tester_fd,
                                           const std::function<void()> &dut_close) {
    if (tester_fd < 0) return {};

    dut_close();
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
    info.ok = true;
    // snd_nxt = ISN_t+1 pre-FIN; +1 for the shutdown FIN consumed → ISN_t+2.
    // rcv_nxt already reflects the consumed DUT FIN (ISN_d+2).
    info.tester_seq_post_fin = seq_pre_fin->snd_nxt + 1U;
    info.tester_ack_post_fin = seq_pre_fin->rcv_nxt;
    return info;
}

// CLOSING path core: given an accepted tester_fd and a DUT-close callback, drive
// DUT ESTABLISHED → FIN-WAIT-1 → CLOSING → TIME-WAIT.
//   1. TesterAutoAckDrop suppresses the kernel pure-ACK auto-reply so the DUT
//      stays in FIN-WAIT-1 (not FIN-WAIT-2) after dut_close()'s FIN.
//   2. A tester FIN+ACK that does NOT ack the DUT FIN crosses it into CLOSING.
//   3. A tester ACK that DOES ack the DUT FIN drives CLOSING → TIME-WAIT.
//   4. TCP_REPAIR + ::close disposes the tester socket without a stray FIN,
//      freeing the 4-tuple for the caller's post-TIME-WAIT replay.
// Consumes tester_fd (closed on every path). ok=false on tester_fd<0 or a failed
// seq snapshot.
inline TcpTimeWaitInfo driveToTimeWaitViaClosing(const ::tc8::TestConfig &cfg,
                                                 std::string_view iface,
                                                 const std::array<std::uint8_t, 6> &dut_mac,
                                                 int tester_fd,
                                                 std::uint16_t local_port,
                                                 std::uint16_t remote_port,
                                                 const std::function<void()> &dut_close) {
    if (tester_fd < 0) return {};

    TesterAutoAckDrop ack_drop(cfg);
    dut_close();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    const auto seq = queryTcpSeqRange(tester_fd);
    if (!seq.has_value()) {
        ::close(tester_fd);
        return {};
    }

    injectTesterFinAck(cfg, iface, dut_mac, local_port, remote_port,
                       seq->snd_nxt, seq->rcv_nxt - 1U);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Tester ACK that DOES ack the DUT FIN → CLOSING → TIME-WAIT.
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

    // TCP_REPAIR-silent dispose: no stray tester FIN on the freed 4-tuple.
    {
        int repair_on = 1;
        ::setsockopt(tester_fd, IPPROTO_TCP, TCP_REPAIR, &repair_on, sizeof(repair_on));
        ::close(tester_fd);
    }

    TcpTimeWaitInfo info{};
    info.ok                  = true;
    info.tester_seq_post_fin = seq->snd_nxt + 1U;
    info.tester_ack_post_fin = seq->rcv_nxt;
    return info;
}

// CLOSING-state core (stops at CLOSING, does NOT advance to TIME-WAIT):
// given an accepted tester_fd and a DUT-close callback, drive DUT
// ESTABLISHED → FIN-WAIT-1 → CLOSING and leave it there. The single source
// of truth for the CLOSING-entry wire mechanics — the seam
// `driveSeamCloseToClosing` (cases/_tcp_seam_time_wait_prelude.h) binds
// `dut_close` and re-implements nothing. Identical to
// `driveToTimeWaitViaClosing` through the non-acking
// FIN+ACK, then it STOPS: the follow-on DUT-FIN-acking ACK and the
// TCP_REPAIR dispose are both omitted, so the DUT stays in CLOSING and the
// caller keeps a live tester_fd.
//
// Caller responsibilities (UNACCEPTABLE_11 / FLAGS_INVALID_12 / ...):
//   1. Install TesterAutoAckDrop in caller scope BEFORE invoking this core
//      — unlike `driveToTimeWaitViaClosing` it does NOT install its own, so
//      the kernel pure-ACK auto-reply stays suppressed (DUT pinned in
//      FIN-WAIT-1) for the caller's whole probe phase, not just this call.
//   2. Use returned info.tester_seq_post_fin / .tester_ack_post_fin as the
//      seq/ack BASE for any subsequent raw-inject probe (OTW SEQ via
//      kOutOfWindowSeqOffset, unacceptable ACK, etc.).
//   3. After the probe phase, silentlyCloseTesterFd(`tester_fd`) to free the
//      4-tuple without emitting a stray FIN+ACK; the TesterAutoAckDrop scope
//      can then end.
//
// Returns ok=false on tester_fd<0 or a failed seq snapshot (tester_fd is
// plain-::close'd on that path so the core does not leak it; otherwise the
// caller owns it). dut_close (a std::function) carries no dut_control.h
// dependency — see the SSOT block comment above injectTesterFinAck.
inline TcpTimeWaitInfo driveToClosingState(
    const ::tc8::TestConfig &cfg,
    std::string_view iface,
    const std::array<std::uint8_t, 6> &dut_mac,
    int           tester_fd,
    std::uint16_t local_port,
    std::uint16_t remote_port,
    const std::function<void()> &dut_close) {
    if (tester_fd < 0) return {};

    dut_close();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    const auto seq = queryTcpSeqRange(tester_fd);
    if (!seq.has_value()) {
        ::close(tester_fd);
        return {};
    }

    // FIN+ACK that does NOT ack the DUT FIN → DUT FIN-WAIT-1 → CLOSING.
    injectTesterFinAck(cfg, iface, dut_mac, local_port, remote_port,
                       seq->snd_nxt, seq->rcv_nxt - 1U);
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
