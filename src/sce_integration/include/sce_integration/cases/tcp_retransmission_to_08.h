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
#include "sce_integration/tcp_captured.h"
#include "sce_integration/tcp_pilot_common.h"
#include "sce_integration/tcp_rto_ceiling.h"
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
// For the spec's <msl> = 30 s, 2*MSL = 60 s.
//
// Verdict mechanism (kernel-side state probe through the seam):
//   1. Active-OPEN handshake on +181 port quad. acceptOne() drains
//      the tester accept queue.
//   2. TesterAutoAckDrop installs an iptables rule suppressing every
//      tester-kernel auto-ACK so the DUT's RTO timer fires
//      uninterrupted.
//   3. Data SEND seg1 (8 B) → DUT data segment 1.
//   4. observeRtoCeiling (tcp_rto_ceiling.h) polls TCP_INFO and ends
//      at the first timeout whose RTO is below twice the previous one
//      (the ceiling), when the RTO passes 63 s, or when the budget
//      runs out.
//   5. SCXML grades the outcome and the last `tcpi_rto`: a ceiling
//      of 60 s ± 5 % passes; an RTO above 63 s, or a ceiling below
//      57 s, fails; no ceiling within the budget is inconclusive.
//
// Budget. From a ~200 ms initial RTO, doubling reaches the step that
// either clamps to 60 s or overshoots to 102.4 s about 103 s after the
// send (0.2 + 0.4 + ... + 51.2). The budget leaves room for that step
// and one poll after it.
template <>
struct TestCaseTraits<cases::TcpRetransmissionTo08SM> {
    using SM    = cases::TcpRetransmissionTo08SM;
    using State = SM::PolicyType::State;
    using Event = SM::PolicyType::Event;

    static constexpr std::string_view kCaseId      = "TCP_RETRANSMISSION_TO_08";
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

    static constexpr auto kPollInterval  = std::chrono::milliseconds(2000);
    static constexpr auto kBudget        = std::chrono::milliseconds(120000);

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        using namespace ::tc8::sce::tcp;

        const std::uint16_t local_port  = static_cast<std::uint16_t>(
            kBasicsActiveLocalPort  + kTcpRetransmissionTo08LocalOffset);
        const std::uint16_t remote_port = static_cast<std::uint16_t>(
            kBasicsActiveRemotePort + kTcpRetransmissionTo08LocalOffset);

        // Active OPEN → ESTABLISHED routed through the backend-agnostic
        // seam; acceptOne() drains the tester accept queue.
        auto open = driveSeamActiveOpen(ctx.dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;
        if (!open.conn) {
            ::close(tester_fd);
            return;
        }
        const ::tc8::sce::DutSocket dut_sock = open.conn->socket;
        c.ut_handshake_completed = true;

        TesterAutoAckDrop ack_drop(cfg);

        seamSendTcp(ctx.dut, dut_sock, kPayload);

        const auto obs = observeRtoCeiling(ctx.dut, dut_sock, kBudget, kPollInterval,
                                           kTwoMslRtoUpperUs);

        c.ut_rto_ceiling         = obs.outcome;
        c.ut_tcpi_p1_valid       = obs.valid;
        c.ut_tcpi_p1_state       = obs.last.state;
        c.ut_tcpi_p1_rto_us      = obs.last.rto_us;
        c.ut_tcpi_p1_retransmits = obs.last.retransmits;
        c.ut_tcpi_p1_unacked     = obs.last.unacked;

        ::close(tester_fd);
    }

    static void dispatch(Captured& /*c*/, SM& /*sm*/, const ::tc8::CapturedEvent& /*ev*/) {
        // Verdict computed from kernel TCP_INFO snapshot — wire frames
        // not consulted.
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpRetransmissionTo08SM, tcp_retransmission_to_08)
