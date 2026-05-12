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

#include "tcp_retransmission_to_04_sm.h"

namespace tc8::sce::cases {

using TcpRetransmissionTo04SM =
    ::SCE::Generated::tcp_retransmission_to_04::tcp_retransmission_to_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpRetransmissionTo04SM> {
    using SM    = cases::TcpRetransmissionTo04SM;
    using State = SM::PolicyType::State;
    using Event = SM::PolicyType::Event;

    static constexpr std::string_view kCaseId       = "TCP_RETRANSMISSION_TO_04";
    static constexpr std::string_view kSpecSection  = "4.8.6.11";
    static constexpr std::string_view kDescription  =
        "DUT TCP MUST include exponential backoff (more than linear) "
        "for successive RTO values for data segments (RFC 1122 "
        "§4.2.3.1 — RFC 6298 §5).";
    static constexpr bool             kDeprecated   = false;
    static constexpr int              kTopology     = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup     = ::tc8::BpfGroup::Tcp;

    using Captured = typename SM::CapturedType;
    using Expected = typename SM::ExpectedType;

    // Single 8 B data segment is enough to exercise
    // `tcp_retransmit_timer`'s exponential-backoff branch — Nagle and
    // MSS are irrelevant at this size. Distinct first byte aids pcap
    // visual inspection during regression diagnosis.
    static constexpr std::array<std::uint8_t, 8> kSegPayload = {
        'P','4','D','a','t','a','0','1'};

    // Per-phase TCP_INFO poll cadence + deadline. Linux's data-RTO
    // sequence on a fresh local-veth ESTABLISHED socket lands retx
    // 1/2/3 at ~200 / 600 / 1400 ms post-seg1 (RTO_MIN=200 ms doubling
    // each fire). Under workers=4 full-suite load the high-resolution
    // timer fire can drift by several hundred ms — observed ~700 ms
    // worst-case across the cluster. Polling instead returns as soon
    // as the kernel reports tcpi_retransmits crossing each threshold
    // (median ~250 ms past nominal; 95-th percentile ~1 s under
    // stress). Per-phase deadlines scale with the doubling pattern
    // so a slow retx 3 doesn't time-budget on the seg-1 envelope.
    static constexpr std::chrono::milliseconds kPollInterval{50};
    static constexpr std::chrono::milliseconds kPhase1Deadline{2000};
    static constexpr std::chrono::milliseconds kPhase2Deadline{3000};
    static constexpr std::chrono::milliseconds kPhase3Deadline{5000};

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort  + kTcpRetransmissionTo04LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpRetransmissionTo04LocalOffset;

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.arp.dut_real_mac,
            /*open_req_id=*/1, local_port, remote_port);
        const int tester_fd = listener.acceptOne();
        if (tester_fd < 0) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            ::close(tester_fd);
            return;
        }

        // Prelude success — the SCXML's first cond gates on this so a
        // negative IP-flip variant lands on
        // `fail_handshake_did_not_complete` instead of the indirect
        // `fail_phase1_query_failed`.
        c.ut_handshake_completed = true;

        // Tester-kernel auto-ACK suppression must outlive every retx
        // observation; RAII over the full stimulus body keeps it
        // active across the three poll loops. Released on stimulus
        // return, which only happens AFTER the third snapshot lands.
        TesterAutoAckDrop ack_drop(cfg);

        // Spec step 2-3: UT SEND → DUT data segment 1. With ack_drop
        // active the tester kernel's auto-ACK is silently dropped on
        // egress; DUT snd_una stays at seg_seq, the retransmit timer
        // fires when icsk_rto elapses, and `tcp_retransmit_timer`
        // takes the "Use normal (exponential) backoff" branch on every
        // fire (state == TCP_ESTABLISHED — `tcp_syn_linear_timeouts`
        // applies only to TCP_SYN_SENT, see
        // [[linux-syn-data-rto-deviations]]).
        sendSendTcpDataRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/2, /*socket_id=*/1,
            kSegPayload.data(),
            static_cast<std::uint16_t>(kSegPayload.size()));

        // Phase 1: poll TCP_INFO until kernel confirms retx 1 fired
        // (tcpi_retransmits >= 1). `_p1_rto_us` after this point
        // reflects the doubled `icsk_rto` value Linux installed when
        // `tcp_retransmit_timer` re-armed.
        const auto phase1_start = std::chrono::steady_clock::now();
        ::tc8::sce::tcp::TcpInfoSnapshot p1{};
        while (true) {
            std::this_thread::sleep_for(kPollInterval);
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

        // Phase 2: poll until retx 2 fires (tcpi_retransmits >= 2).
        // Per RFC 6298 §5 step 5.5 + Linux's `tcp_retransmit_timer`
        // doubling: `_p2_rto_us` MUST exceed `_p1_rto_us`. A linear
        // (constant-RTO) DUT would leave p2.rto_us == p1.rto_us — the
        // SCXML's strict-growth cond rejects it.
        const auto phase2_start = std::chrono::steady_clock::now();
        ::tc8::sce::tcp::TcpInfoSnapshot p2{};
        while (true) {
            std::this_thread::sleep_for(kPollInterval);
            p2 = queryTcpInfoSync(cfg, /*req_id=*/4, /*socket_id=*/1);
            if (!p2.valid) break;
            if (p2.retransmits >= 2) break;
            if (std::chrono::steady_clock::now() - phase2_start >= kPhase2Deadline) break;
        }
        c.ut_tcpi_p2_valid       = p2.valid;
        c.ut_tcpi_p2_state       = p2.state;
        c.ut_tcpi_p2_rto_us      = p2.rto_us;
        c.ut_tcpi_p2_retransmits = p2.retransmits;
        c.ut_tcpi_p2_unacked     = p2.unacked;

        // Phase 3: poll until retx 3 fires (tcpi_retransmits >= 3).
        // Same strict-growth assertion: p3.rto_us > p2.rto_us proves
        // the kernel doubled icsk_rto a third time. Three observations
        // of strict growth across the cluster pin the "more than
        // linear" RFC 1122 §4.2.3.1 / RFC 6298 §5 MUST.
        const auto phase3_start = std::chrono::steady_clock::now();
        ::tc8::sce::tcp::TcpInfoSnapshot p3{};
        while (true) {
            std::this_thread::sleep_for(kPollInterval);
            p3 = queryTcpInfoSync(cfg, /*req_id=*/5, /*socket_id=*/1);
            if (!p3.valid) break;
            if (p3.retransmits >= 3) break;
            if (std::chrono::steady_clock::now() - phase3_start >= kPhase3Deadline) break;
        }
        c.ut_tcpi_p3_valid       = p3.valid;
        c.ut_tcpi_p3_state       = p3.state;
        c.ut_tcpi_p3_rto_us      = p3.rto_us;
        c.ut_tcpi_p3_retransmits = p3.retransmits;
        c.ut_tcpi_p3_unacked     = p3.unacked;

        (void)tester_fd;
    }

    static void dispatch(Captured& /*c*/, SM& /*sm*/, const ::tc8::CapturedEvent& /*ev*/) {
        // Verdict is computed from kernel-side TCP_INFO snapshots
        // populated synchronously in `stimulus()` — wire frames are
        // not consulted, so frame ingress is intentionally a no-op.
        // The SM advances purely on the `<send event="evaluate"
        // delay="0ms"/>` raise in `<onentry>` of the initial state.
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                              return "pass";
            case State::Fail_handshake_did_not_complete:   return "fail:dut_handshake_did_not_complete";
            case State::Fail_phase1_query_failed:          return "fail:phase1_tcp_info_query_failed";
            case State::Fail_phase2_query_failed:          return "fail:phase2_tcp_info_query_failed";
            case State::Fail_phase3_query_failed:          return "fail:phase3_tcp_info_query_failed";
            case State::Fail_no_retx_1:                    return "fail:no_dut_data_retransmit_1";
            case State::Fail_no_retx_2:                    return "fail:no_dut_data_retransmit_2";
            case State::Fail_no_retx_3:                    return "fail:no_dut_data_retransmit_3";
            case State::Fail_initial_rto_not_doubled:      return "fail:phase1_rto_below_doubled_baseline";
            case State::Fail_retx2_not_doubled:            return "fail:phase2_rto_not_greater_than_phase1";
            case State::Fail_retx3_not_doubled:            return "fail:phase3_rto_not_greater_than_phase2";
            default:                                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpRetransmissionTo04SM, tcp_retransmission_to_04)
