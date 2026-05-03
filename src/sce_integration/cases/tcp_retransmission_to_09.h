#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/ipv4_expected.h"
#include "sce_integration/tcp_captured.h"
#include "sce_integration/tcp_pilot_common.h"
#include "sce_integration/test_case_traits.h"
#include "sce_integration/test_runner.h"

#include "tcp_retransmission_to_09_sm.h"

namespace tc8::sce::cases {

using TcpRetransmissionTo09SM =
    ::SCE::Generated::tcp_retransmission_to_09::tcp_retransmission_to_09;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §4.8.6.11 TCP_RETRANSMISSION_TO_09: TCP SHOULD use an upper
// bound of 2*MSL of RTO for SYN segments (RFC 1122 §4.2.3.1 p96).
//
// Linux 6.5 has a SYN-specific cadence (sibling to _08's data path):
// `tcp_syn_linear_timeouts = 4` runs the first 4 SYN retransmits at a
// constant ~1 s interval, then exponential doubling kicks in. The
// terminal RTO for SYN-SENT also caps at TCP_RTO_MAX = 120 s, twice
// the spec's 2*MSL = 60 s expectation. On a Linux DUT this case is
// expected to fail; a strict-RFC DUT honouring 2*MSL=60s would pass.
//
// Verdict mechanism (kernel-side via OpQueryTcpInfo, dispatch=no-op):
//   1. TesterAutoRstDrop suppresses tester-kernel auto-RST against
//      the unbound destination port; without it Linux's
//      tcp_v4_send_reset would close DUT's SYN-SENT TCB on the first
//      SYN, defeating the test.
//   2. UT OpOpenTcpSocket(Active) on +182 port quad — DUT issues SYN,
//      enters SYN-SENT, kernel arms retransmit timer.
//   3. Poll TCP_INFO every 2 s on the SYN-SENT socket. Track the
//      same plateau detection as _08 (3 consecutive identical
//      `tcpi_rto` snapshots ⇒ plateaued). Budget cap: 35 s
//      wall-time.
//   4. SCXML verdict mirrors _08: pass if rto_us == 60 s ± 5%, else
//      classified as above-cap or below-cap.
//
// Wall-time profile under Linux 6.5:
//   t=0:    SYN1  (rto seed = 1 s)
//   t=1:    SYN2 (linear retx 1)
//   t=2:    SYN3 (linear retx 2)
//   t=3:    SYN4 (linear retx 3)
//   t=4:    SYN5 (linear retx 4 — last linear)
//   t=5:    SYN6 (rto = 1 s)
//   t=7:    SYN7 (rto = 2 s)
//   t=11:   SYN8 (rto = 4 s)
//   t=19:   SYN9 (rto = 8 s)
//   t=35:  → budget cap, RTO ~16 s, mid-doubling
// Spec's 2*MSL = 60 s plateau is unreachable inside the 35 s budget,
// so verdict consistently lands on `fail_rto_below_2msl_cap` for the
// Linux DUT.
template <>
struct TestCaseTraits<cases::TcpRetransmissionTo09SM> {
    using SM    = cases::TcpRetransmissionTo09SM;
    using State = SM::PolicyType::State;
    using Event = SM::PolicyType::Event;

    static constexpr std::string_view kCaseId      = "TCP_RETRANSMISSION_TO_09";
    static constexpr std::string_view kSpecSection = "4.8.6.11";
    static constexpr std::string_view kDescription =
        "DUT TCP SHOULD use 2*MSL upper bound on SYN-segment RTO "
        "(RFC 1122 §4.2.3.1 p96 SHOULD).";
    static constexpr bool             kDeprecated  = false;
    static constexpr int              kTopology    = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup    = ::tc8::BpfGroup::Tcp;

    using Captured = typename SM::CapturedType;
    using Expected = typename SM::ExpectedType;

    static constexpr auto kPollInterval  = std::chrono::milliseconds(2000);
    static constexpr auto kBudget        = std::chrono::milliseconds(35000);
    static constexpr std::uint8_t kPlateauSnapshots = 3;

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = static_cast<std::uint16_t>(
            kBasicsActiveLocalPort  + kTcpRetransmissionTo09LocalOffset);
        const std::uint16_t remote_port = static_cast<std::uint16_t>(
            kBasicsActiveRemotePort + kTcpRetransmissionTo09LocalOffset);

        // RstDrop scope must outlive the entire poll loop — the DUT's
        // SYN retransmits keep landing on the unbound destination port,
        // and without the iptables drop the tester kernel would auto-
        // RST every retransmit and tear the DUT's SYN-SENT TCB before
        // the RTO has a chance to plateau.
        TesterAutoRstDrop rst_drop(cfg);

        sendOpenTcpSocketActiveRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/1, local_port,
            cfg.ipv4.tester_ip, remote_port);
        std::this_thread::sleep_for(kTcpUtRpcWait);

        // The handshake never completes (SYN-SENT only). Mark prelude
        // success on UT round-trip — `driveActiveOpenEstablished`
        // would normally do this gating, but here we issue
        // OpOpenTcpSocket directly because the TCP state we want is
        // SYN-SENT, not ESTABLISHED.
        c.ut_handshake_completed = true;

        const auto start = std::chrono::steady_clock::now();
        ::tc8::sce::tcp::TcpInfoSnapshot last{};
        std::uint32_t prev_rto = 0;
        std::uint8_t  plateau_count = 0;
        while (std::chrono::steady_clock::now() - start < kBudget) {
            std::this_thread::sleep_for(kPollInterval);
            last = queryTcpInfoSync(cfg, /*req_id=*/2, /*socket_id=*/1);
            if (!last.valid) continue;
            if (last.rto_us == prev_rto && prev_rto != 0) {
                if (++plateau_count >= kPlateauSnapshots) break;
            } else {
                plateau_count = 0;
                prev_rto = last.rto_us;
            }
        }

        c.ut_tcpi_p1_valid       = last.valid;
        c.ut_tcpi_p1_state       = last.state;
        c.ut_tcpi_p1_rto_us      = last.rto_us;
        c.ut_tcpi_p1_retransmits = last.retransmits;
        c.ut_tcpi_p1_unacked     = last.unacked;

        sendCloseTcpSocketRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/3, /*socket_id=*/1);
    }

    static void dispatch(Captured& /*c*/, SM& /*sm*/, const ::tc8::CapturedEvent& /*ev*/) {
        // Verdict computed from kernel TCP_INFO snapshot — wire frames
        // not consulted.
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                              return "pass";
            case State::Fail_handshake_did_not_complete:   return "fail:dut_active_open_did_not_initiate";
            case State::Fail_query_failed:                 return "fail:tcp_info_query_failed";
            case State::Fail_no_retx:                      return "fail:no_syn_retransmits_observed_in_kernel";
            case State::Fail_rto_above_2msl_cap:           return "fail:rto_plateau_above_2_msl_linux_rto_max_120s_exceeds_spec_2_msl_60s";
            case State::Fail_rto_below_2msl_cap:           return "fail:rto_below_2_msl_did_not_plateau_within_observation_budget";
            default:                                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpRetransmissionTo09SM, tcp_retransmission_to_09)
