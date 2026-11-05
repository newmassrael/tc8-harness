#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/ipv4_expected.h"
#include "sce_integration/tcp_case_captured.h"
#include "sce_integration/tcp_observation.h"
#include "sce_integration/tcp_pilot_common.h"
#include "sce_integration/tcp_retransmission_series.h"
#include "sce_integration/test_case_traits.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_retransmission_to_03_sm.h"

namespace tc8::sce::cases {

using TcpRetransmissionTo03SM =
    ::SCE::Generated::tcp_retransmission_to_03::tcp_retransmission_to_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpRetransmissionTo03SM> {
    using SM    = cases::TcpRetransmissionTo03SM;
    using State = SM::PolicyType::State;
    using Event = SM::PolicyType::Event;

    static constexpr std::string_view kCaseId       = "TCP_RETRANSMISSION_TO_03";
    static constexpr std::string_view kDescription  =
        "DUT TCP MUST follow Karn's algorithm — preserve RTO doubling "
        "across an ACK that acknowledges a previously retransmitted "
        "segment (RFC 1122 §4.2.3.1 — RFC 6298 §3 / §5).";
    static constexpr bool             kDeprecated   = false;
    static constexpr int              kTopology     = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup     = ::tc8::BpfGroup::Tcp;

    // The verdict reads the DUT's kernel RTO/retransmit counters
    // (tcpi_rto, tcpi_retransmits, tcpi_unacked) — a state introspection
    // the opcode UT exposes (OpQueryTcpInfo) but the standard AUTOSAR
    // testability protocol does not. Declaring kCapTcpInfoProbe makes the
    // CLI capability gate honestly SKIP this case on a testability backend
    // (Tier 2 2b#4) instead of failing it; kCapTcpControl covers the active
    // open + data send themselves.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpInfoProbe;

    using Captured = typename SM::CapturedType;
    using Expected = typename SM::ExpectedType;

    static constexpr std::array<std::uint8_t, 8> kPhase1Payload = {
        'P','3','S','1','d','a','t','a'};
    static constexpr std::array<std::uint8_t, 8> kPhase2Payload = {
        'P','3','S','2','d','a','t','a'};

    // The DUT sends seg1 as soon as the SEND reaches it. Its retransmission is then
    // waited for as long as the DUT's own RTO says (tcp_retransmission_series.h), not
    // for a fixed 3 s, which a sender with the RFC 1122 3 s initial RTO would miss.
    static constexpr std::chrono::milliseconds kFirstSegmentBound{5000};

    // Phase-2 TCP_INFO poll cadence + deadline. After the Karn-
    // excluded ACK + seg2 send, the kernel rearms the retx timer
    // sub-millisecond — but the seam round-trip + the DUT's ::send
    // between the send call returning and seg2 actually hitting the
    // wire can take hundreds of ms under load. Polling until
    // `tcpi_unacked >= 1` confirms seg2 is in-flight (timer armed at
    // the current `icsk_rto` value); deadline 1 s is an order of
    // magnitude past observed worst-case. Symmetric with the phase-1
    // poll so a future contributor sees one consistent pattern
    // instead of "phase 1 polls, phase 2 sleeps fixed."
    static constexpr std::chrono::milliseconds kPhase2PollInterval{50};
    static constexpr std::chrono::milliseconds kPhase2Deadline{1000};

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        using namespace ::tc8::sce::tcp;

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort  + kTcpRetransmissionTo03LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpRetransmissionTo03LocalOffset;

        // Active OPEN → ESTABLISHED routed through the backend-agnostic
        // seam (driveSeamActiveOpen binds the tester-side listener and
        // issues the DUT's CREATE_AND_BIND + CONNECT). The tester fd is
        // grabbed off the auxiliary listener for the in-window seq probe.
        auto open = driveSeamActiveOpen(ctx.dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value() || !open.conn) {
            ::close(tester_fd);
            return;
        }
        const ::tc8::sce::DutSocket dut_sock = open.conn->socket;

        // Mark prelude success — the SCXML's first cond gates on
        // this so a negative IP-flip flow lands on
        // `inconclusive_handshake_did_not_complete` instead of the indirect
        // `error_phase1_query_failed`.
        c.ut_handshake_completed = true;

        const std::uint32_t phase1_seq = seq_range->rcv_nxt;
        const auto phase1_len = static_cast<std::uint32_t>(kPhase1Payload.size());
        const std::uint32_t phase2_ack = phase1_seq + phase1_len;
        const std::uint32_t tester_snd = seq_range->snd_nxt;

        // Drop tester-kernel auto-ACKs throughout both phases. RAII
        // uninstalls the iptables rule when stimulus returns; the
        // SCXML's verdict has already been computed off the captured
        // TCP_INFO snapshots by then.
        TesterAutoAckDrop ack_drop(cfg);

        // Spec steps 2-6: seg1, then its one retransmission, waited for as long as
        // the DUT's own RTO says it will take (tcp_retransmission_series.h). The RTO
        // the DUT held while seg1 was in flight is the one the specification notes
        // (`initial_rto_us`); the RTO after the retransmission is the backed-off one.
        const std::uint32_t dut_ip = cfg.dut.ip;
        const ::tc8::sce::ObservationCursor before_send = ctx.observer.mark();
        seamSendTcp(ctx.dut, dut_sock, kPhase1Payload);
        const auto first = ctx.observer.awaitObservation(
            "dut_data_segment", before_send,
            dutDataSegmentAt(dut_ip, local_port, phase1_seq, phase1_len), kFirstSegmentBound);
        if (!first) return;
        watchRetransmissions(
            c, ctx, dut_sock, before_send,
            [dut_ip, local_port, phase1_seq, phase1_len](std::int64_t after_ts_us) {
                return dutDataSegmentAt(dut_ip, local_port, phase1_seq, phase1_len, after_ts_us);
            },
            segmentOf(first->view()).observed_ts_us, /*count=*/1,
            {"dut_data_retransmission_1", "", ""});
        if (c.retransmissions_seen < 1) return;

        // Spec steps 7-9: raw-inject an ACK of the retransmitted seg1 (snd_una
        // advances past seg1; RFC 6298 §3 / §5.3 forbid the RTT estimator from
        // sampling this round-trip, since the ACK cannot be attributed to either
        // copy), then send seg2. A Karn-correct DUT sends seg2 under the backed-off
        // RTO; a DUT that samples the ambiguous round-trip recomputes it. This raw
        // inject is tester-side and stays off the seam.
        ::tc8::stimulus::TcpSegmentSpec ack_seg{};
        ack_seg.src_port = remote_port;
        ack_seg.dst_port = local_port;
        ack_seg.seq_num  = tester_snd;
        ack_seg.ack_num  = phase2_ack;
        ack_seg.flags    = ::tc8::stimulus::kTcpFlagAck;
        ack_seg.window   = 65535U;
        ::tc8::sce::tcp::emitTcpFrame(
            cfg, ctx.iface, cfg.dut.mac, ack_seg,
            /*initial_wait=*/std::chrono::milliseconds(0));

        seamSendTcp(ctx.dut, dut_sock, kPhase2Payload);

        // Poll until the kernel confirms seg2 is in-flight
        // (tcpi_unacked >= 1 ⇒ timer armed at the current icsk_rto
        // value the SCXML verdicts on). Symmetric with phase-1's
        // poll-until-condition pattern, same retry-on-invalid.
        const auto phase2_start = std::chrono::steady_clock::now();
        ::tc8::sce::DutTcpInfo p2{};
        bool p2_valid = false;
        while (true) {
            std::this_thread::sleep_for(kPhase2PollInterval);
            const auto probe = ctx.dut.tcpInfoProbe()->queryInfo(dut_sock);
            if (probe) {
                p2 = *probe;
                p2_valid = true;
                if (p2.unacked >= 1) break;
            }
            if (std::chrono::steady_clock::now() - phase2_start >= kPhase2Deadline) break;
        }
        c.ut_tcpi_p2_valid       = p2_valid;
        c.ut_tcpi_p2_state       = p2.state;
        c.ut_tcpi_p2_rto_us      = p2.rto_us;
        c.ut_tcpi_p2_retransmits = p2.retransmits;
        c.ut_tcpi_p2_unacked     = p2.unacked;

        // Tester fd is intentionally left open (matching the pre-seam
        // flow): the verdict is already captured, and closing here would
        // emit a tester FIN the original procedure never sent. The
        // listener RAII reaps the listen fd; the accepted fd is released
        // at harness process teardown after the case.
        (void)tester_fd;
    }

    static void dispatch(Captured& /*c*/, SM& /*sm*/, const ::tc8::CapturedEvent& /*ev*/) {
        // Verdict is computed from kernel-side TCP_INFO snapshots
        // populated synchronously in `stimulus()` — wire frames are
        // not consulted, so frame ingress is intentionally a no-op.
        // The SM advances purely on the `<send event="evaluate"
        // delay="0ms"/>` raise in `<onentry>` of the initial state,
        // which the SCE scheduler dispatches into the next macrostep.
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpRetransmissionTo03SM, tcp_retransmission_to_03)
