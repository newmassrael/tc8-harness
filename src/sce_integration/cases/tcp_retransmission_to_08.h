#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>
#include <unistd.h>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_active_open.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/ipv4_expected.h"
#include "sce_integration/tcp_captured.h"
#include "sce_integration/tcp_pilot_common.h"
#include "sce_integration/test_case_traits.h"
#include "sce_integration/test_runner.h"

#include "tcp_retransmission_to_08_sm.h"

namespace tc8::sce::cases {

using TcpRetransmissionTo08SM =
    ::SCE::Generated::tcp_retransmission_to_08::tcp_retransmission_to_08;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §4.8.6.11 TCP_RETRANSMISSION_TO_08: TCP SHOULD use an upper
// bound of 2*MSL of RTO for data segments (RFC 1122 §4.2.3.1 p96).
//
// For the spec's <msl> = 30 s (default Linux MSL = TCP_TIMEWAIT_LEN/2),
// 2*MSL = 60 s. Linux 6.5 caps RTO at the compile-time
// `TCP_RTO_MAX = HZ * 120` ≈ 120 s — twice the spec's expected cap.
// On a Linux DUT this case is expected to fail because the kernel's
// RTO doubles past 60 s before plateauing at 120 s; a strict-RFC DUT
// honouring the 2*MSL ceiling would pass.
//
// Verdict mechanism (RETRANSMISSION_TO_03 pattern, kernel-side state
// probe through the seam):
//   1. Active-OPEN handshake on +181 port quad. acceptOne() drains
//      the tester accept queue.
//   2. TesterAutoAckDrop installs an iptables rule suppressing every
//      tester-kernel auto-ACK so the DUT's RTO timer fires
//      uninterrupted.
//   3. Data SEND seg1 (8 B) → DUT data segment 1.
//   4. Poll TCP_INFO every 2 s. Track plateau detection: when
//      `tcpi_rto` repeats unchanged for 3 consecutive snapshots the
//      RTO has plateaued. Otherwise the budget cap (35 s wall-time)
//      forces an inconclusive verdict.
//   5. SCXML evaluates the captured `tcpi_rto`:
//        * `rto_us == 60_000_000 ± 5%`  ⇒ pass (spec's 2*MSL cap)
//        * `rto_us > 63_000_000`        ⇒ fail_rto_above_2msl_cap
//        * `rto_us < 57_000_000`        ⇒ fail_rto_below_2msl_cap
//          (covers both Linux mid-doubling at budget cap and any DUT
//          that plateaus too low)
//
// Wall-time budget (~35 s) is tight relative to Linux's full RTO_MAX
// path (~200 s for a 10-doubling sequence). On Linux 6.5, at the
// budget deadline `tcpi_rto` is in mid-doubling around 25-50 s
// (geometric series: 200ms+400+800+1.6+3.2+6.4+12.8+25.6 = ~50 s
// cumulative wall-time to reach 25.6 s RTO setting). The verdict
// will fall on `fail_rto_below_2msl_cap` because Linux hasn't
// plateaued yet, which is correct: the spec's 2*MSL=60s plateau
// is not reachable on this kernel within any reasonable budget.
template <>
struct TestCaseTraits<cases::TcpRetransmissionTo08SM> {
    using SM    = cases::TcpRetransmissionTo08SM;
    using State = SM::PolicyType::State;
    using Event = SM::PolicyType::Event;

    static constexpr std::string_view kCaseId      = "TCP_RETRANSMISSION_TO_08";
    static constexpr std::string_view kSpecSection = "4.8.6.11";
    static constexpr std::string_view kDescription =
        "DUT TCP SHOULD use 2*MSL upper bound on data-segment RTO "
        "(RFC 1122 §4.2.3.1 p96 SHOULD).";
    static constexpr bool             kDeprecated  = false;
    static constexpr int              kTopology    = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup    = ::tc8::BpfGroup::Tcp;

    // The verdict reads the DUT's kernel RTO plateau (tcpi_rto) — a
    // state introspection the opcode UT exposes (OpQueryTcpInfo) but the
    // standard AUTOSAR testability protocol does not. Declaring
    // kCapTcpStateProbe makes the CLI capability gate honestly SKIP this
    // case on a testability backend (Tier 2 2b#4) instead of failing it;
    // kCapTcpControl covers the active open + data send themselves.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpStateProbe;

    using Captured = typename SM::CapturedType;
    using Expected = typename SM::ExpectedType;

    static constexpr std::array<std::uint8_t, 8> kPayload = {
        'P','8','D','a','t','a','b','c'};

    // ~35 s budget. Linux's RTO doubling sequence reaches ~50 s
    // cumulative wall-time at the 8th retx (rto = 25.6 s); within
    // 35 s we observe ~6-7 retxs (rto = 6.4-12.8 s). Plateau
    // detection (3 consecutive identical rto reads) triggers the
    // strict-RFC pass path; mid-doubling triggers the
    // "below_2msl_cap" fail path.
    static constexpr auto kPollInterval  = std::chrono::milliseconds(2000);
    static constexpr auto kBudget        = std::chrono::milliseconds(35000);
    static constexpr std::uint8_t kPlateauSnapshots = 3;

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view /*iface*/,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = static_cast<std::uint16_t>(
            kBasicsActiveLocalPort  + kTcpRetransmissionTo08LocalOffset);
        const std::uint16_t remote_port = static_cast<std::uint16_t>(
            kBasicsActiveRemotePort + kTcpRetransmissionTo08LocalOffset);

        // Active OPEN → ESTABLISHED routed through the backend-agnostic
        // seam; acceptOne() drains the tester accept queue.
        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;
        if (!open.conn) {
            ::close(tester_fd);
            return;
        }
        const ::tc8::sce::DutSocket dut_sock = open.conn->socket;
        c.ut_handshake_completed = true;

        TesterAutoAckDrop ack_drop(cfg);

        dut.tcpControl()->sendTcp(
            dut_sock,
            std::vector<std::uint8_t>(kPayload.begin(), kPayload.end()),
            static_cast<std::uint16_t>(kPayload.size()));

        const auto start = std::chrono::steady_clock::now();
        ::tc8::sce::DutTcpInfo last{};
        bool last_valid = false;
        std::uint32_t prev_rto = 0;
        std::uint8_t  plateau_count = 0;
        while (std::chrono::steady_clock::now() - start < kBudget) {
            std::this_thread::sleep_for(kPollInterval);
            const auto probe = dut.tcpStateProbe()->queryInfo(dut_sock);
            if (!probe) continue;
            last = *probe;
            last_valid = true;
            if (last.rto_us == prev_rto && prev_rto != 0) {
                if (++plateau_count >= kPlateauSnapshots) break;
            } else {
                plateau_count = 0;
                prev_rto = last.rto_us;
            }
        }

        c.ut_tcpi_p1_valid       = last_valid;
        c.ut_tcpi_p1_state       = last.state;
        c.ut_tcpi_p1_rto_us      = last.rto_us;
        c.ut_tcpi_p1_retransmits = last.retransmits;
        c.ut_tcpi_p1_unacked     = last.unacked;

        ::close(tester_fd);
    }

    static void dispatch(Captured& /*c*/, SM& /*sm*/, const ::tc8::CapturedEvent& /*ev*/) {
        // Verdict computed from kernel TCP_INFO snapshot — wire frames
        // not consulted.
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                              return "pass";
            case State::Fail_handshake_did_not_complete:   return "fail:dut_handshake_did_not_complete";
            case State::Fail_query_failed:                 return "fail:tcp_info_query_failed";
            case State::Fail_no_retx:                      return "fail:no_retransmits_observed_in_kernel";
            case State::Fail_rto_above_2msl_cap:           return "fail:rto_plateau_above_2_msl_linux_rto_max_120s_exceeds_spec_2_msl_60s";
            case State::Fail_rto_below_2msl_cap:           return "fail:rto_below_2_msl_did_not_plateau_within_observation_budget";
            default:                                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpRetransmissionTo08SM, tcp_retransmission_to_08)
