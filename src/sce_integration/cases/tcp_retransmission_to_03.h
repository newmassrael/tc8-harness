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
#include "sce_integration/ipv4_expected.h"
#include "sce_integration/tcp_captured.h"
#include "sce_integration/tcp_pilot_common.h"
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
    static constexpr std::string_view kSpecSection  = "4.8.6.11";
    static constexpr std::string_view kDescription  =
        "DUT TCP MUST follow Karn's algorithm — preserve RTO doubling "
        "across an ACK that acknowledges a previously retransmitted "
        "segment (RFC 1122 §4.2.3.1 — RFC 6298 §3 / §5).";
    static constexpr bool             kDeprecated   = false;
    static constexpr int              kTopology     = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup     = ::tc8::BpfGroup::Tcp;

    using Captured = typename SM::CapturedType;
    using Expected = typename SM::ExpectedType;

    static constexpr std::array<std::uint8_t, 8> kPhase1Payload = {
        'P','3','S','1','d','a','t','a'};
    static constexpr std::array<std::uint8_t, 8> kPhase2Payload = {
        'P','3','S','2','d','a','t','a'};

    // Phase-1 TCP_INFO poll cadence + deadline. Linux's
    // `tcp_retransmit_timer` first fires at TCP_RTO_MIN ≈ 200 ms
    // baseline, but under workers=4 full-suite CPU load the
    // high-resolution timer fire can be delayed by several hundred
    // milliseconds — observed ~700 ms drift in production
    // reproductions. A fixed sleep had to be conservatively long
    // enough for the worst case, which would have ballooned the
    // case wall-time. Polling instead returns as soon as the kernel
    // reports `tcpi_retransmits >= 1` (median: ~250 ms; 95-th
    // percentile under stress: ~1 s; deadline 3 s as a hard safety
    // net before the case verdicts as fail_no_phase1_retx).
    static constexpr std::chrono::milliseconds kPhase1PollInterval{50};
    static constexpr std::chrono::milliseconds kPhase1Deadline{3000};

    // Phase-2 TCP_INFO poll cadence + deadline. After the Karn-
    // excluded ACK + UT SEND seg2, the kernel rearms the retx timer
    // sub-millisecond — but the UT round-trip + tc8-dut ::send call
    // between `sendSendTcpDataRequest` returning and seg2 actually
    // hitting the wire can take hundreds of ms under load. Polling
    // until `tcpi_unacked >= 1` confirms seg2 is in-flight (timer
    // armed at the current `icsk_rto` value); deadline 1 s is an
    // order of magnitude past observed worst-case. Symmetric with
    // the phase-1 poll so a future contributor sees one consistent
    // pattern instead of "phase 1 polls, phase 2 sleeps fixed."
    static constexpr std::chrono::milliseconds kPhase2PollInterval{50};
    static constexpr std::chrono::milliseconds kPhase2Deadline{1000};

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort  + kTcpRetransmissionTo03LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpRetransmissionTo03LocalOffset;

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.dut.mac,
            /*open_req_id=*/1, local_port, remote_port);
        const int tester_fd = listener.acceptOne();
        if (tester_fd < 0) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            ::close(tester_fd);
            return;
        }

        // Mark prelude success — the SCXML's first cond gates on
        // this so a negative IP-flip flow lands on
        // `fail_handshake_did_not_complete` instead of the indirect
        // `fail_phase1_query_failed`.
        c.ut_handshake_completed = true;

        const std::uint32_t phase1_seq = seq_range->rcv_nxt;
        const std::uint32_t phase2_ack = phase1_seq +
            static_cast<std::uint32_t>(kPhase1Payload.size());
        const std::uint32_t tester_snd = seq_range->snd_nxt;

        // Drop tester-kernel auto-ACKs throughout both phases. RAII
        // uninstalls the iptables rule when stimulus returns; the
        // SCXML's verdict has already been computed off the captured
        // TCP_INFO snapshots by then.
        TesterAutoAckDrop ack_drop(cfg);

        // Phase 1: UT SEND seg1, poll TCP_INFO until kernel confirms
        // retx fired.
        sendSendTcpDataRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/2, /*socket_id=*/1,
            kPhase1Payload.data(),
            static_cast<std::uint16_t>(kPhase1Payload.size()));

        const auto phase1_start = std::chrono::steady_clock::now();
        ::tc8::sce::tcp::TcpInfoSnapshot p1{};
        while (true) {
            std::this_thread::sleep_for(kPhase1PollInterval);
            p1 = queryTcpInfoSync(cfg, /*req_id=*/3, /*socket_id=*/1);
            if (!p1.valid) break;
            if (p1.retransmits >= 1) break;
            if (std::chrono::steady_clock::now() - phase1_start >= kPhase1Deadline) break;
        }
        c.ut_tcpi_p1_valid       = p1.valid;
        c.ut_tcpi_p1_state       = p1.state;
        c.ut_tcpi_p1_rto_us      = p1.rto_us;
        c.ut_tcpi_p1_retransmits = p1.retransmits;
        c.ut_tcpi_p1_unacked     = p1.unacked;

        // Phase 2: raw-inject Karn-excluded ACK acknowledging seg1
        // (snd_una advances past seg1; RFC 6298 §3 / §5.3 forbids the
        // RTT estimator from sampling this round-trip and forbids the
        // retransmission timer from being reset). Then UT SEND seg2
        // — Linux arms the new timer with the *current* `icsk_rto`,
        // so a Karn-correct DUT's tcpi_rto stays at the doubled value
        // observed in phase 1 while a Karn-violating DUT collapses it
        // back to TCP_RTO_MIN baseline (200 ms).
        ::tc8::stimulus::TcpSegmentSpec ack_seg{};
        ack_seg.src_port = remote_port;
        ack_seg.dst_port = local_port;
        ack_seg.seq_num  = tester_snd;
        ack_seg.ack_num  = phase2_ack;
        ack_seg.flags    = ::tc8::stimulus::kTcpFlagAck;
        ack_seg.window   = 65535U;
        ::tc8::sce::tcp::emitTcpFrame(
            cfg, iface, cfg.dut.mac, ack_seg,
            /*initial_wait=*/std::chrono::milliseconds(0));

        sendSendTcpDataRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/4, /*socket_id=*/1,
            kPhase2Payload.data(),
            static_cast<std::uint16_t>(kPhase2Payload.size()));

        // Poll until the kernel confirms seg2 is in-flight
        // (tcpi_unacked >= 1 ⇒ timer armed at the current icsk_rto
        // value the SCXML verdicts on). Symmetric with phase-1's
        // poll-until-condition pattern.
        const auto phase2_start = std::chrono::steady_clock::now();
        ::tc8::sce::tcp::TcpInfoSnapshot p2{};
        while (true) {
            std::this_thread::sleep_for(kPhase2PollInterval);
            p2 = queryTcpInfoSync(cfg, /*req_id=*/5, /*socket_id=*/1);
            if (!p2.valid) break;
            if (p2.unacked >= 1) break;
            if (std::chrono::steady_clock::now() - phase2_start >= kPhase2Deadline) break;
        }
        c.ut_tcpi_p2_valid       = p2.valid;
        c.ut_tcpi_p2_state       = p2.state;
        c.ut_tcpi_p2_rto_us      = p2.rto_us;
        c.ut_tcpi_p2_retransmits = p2.retransmits;
        c.ut_tcpi_p2_unacked     = p2.unacked;

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

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                              return "pass";
            case State::Fail_handshake_did_not_complete:   return "fail:dut_handshake_did_not_complete";
            case State::Fail_phase1_query_failed:          return "fail:phase1_tcp_info_query_failed";
            case State::Fail_phase2_query_failed:          return "fail:phase2_tcp_info_query_failed";
            case State::Fail_no_phase1_retx:               return "fail:no_phase1_retransmit_observed_in_kernel";
            case State::Fail_initial_rto_not_doubled:      return "fail:phase1_rto_below_doubled_baseline";
            case State::Fail_doubling_not_preserved:       return "fail:phase2_rto_not_doubled_karns_violation";
            default:                                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpRetransmissionTo03SM, tcp_retransmission_to_03)
