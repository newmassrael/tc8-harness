#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

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

#include "tcp_retransmission_to_09_sm.h"

namespace tc8::sce::cases {

using TcpRetransmissionTo09SM =
    ::SCE::Generated::tcp_retransmission_to_09::tcp_retransmission_to_09;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §4.8.6.11 TCP_RETRANSMISSION_TO_09: TCP SHOULD use an upper
// bound of 2*MSL of RTO for SYN segments (RFC 1122 §4.2.3.1 p96).
//
// Verdict mechanism (kernel-side state probe through the seam,
// dispatch=no-op):
//   1. TesterAutoRstDrop suppresses tester-kernel auto-RST against
//      the unbound destination port; without it Linux's
//      tcp_v4_send_reset would close DUT's SYN-SENT TCB on the first
//      SYN, defeating the test.
//   2. Active OPEN on +182 port quad — DUT issues SYN, enters
//      SYN-SENT, kernel arms retransmit timer. No tester listener, so
//      the SYN goes unanswered and the socket stays in SYN-SENT.
//   3. observeRtoCeiling (tcp_rto_ceiling.h) polls TCP_INFO on the
//      SYN-SENT socket, exactly as _08 does on its data segment.
//   4. SCXML verdict mirrors _08, plus one outcome of its own: a DUT
//      that gives up the connection before its RTO reaches a ceiling
//      leaves nothing to grade (inconclusive).
//
// Budget. From the RFC 6298 §2.1 initial RTO of 1 s, doubling reaches
// the step that clamps to 60 s or overshoots to 64 s about 63 s after
// the SYN (1 + 2 + ... + 32). A stack that first holds its SYN
// timeouts flat (Linux's tcp_syn_linear_timeouts) needs a few seconds
// more; the budget covers both.
template <>
struct TestCaseTraits<cases::TcpRetransmissionTo09SM> {
    using SM    = cases::TcpRetransmissionTo09SM;
    using State = SM::PolicyType::State;
    using Event = SM::PolicyType::Event;

    static constexpr std::string_view kCaseId      = "TCP_RETRANSMISSION_TO_09";
    static constexpr std::string_view kDescription =
        "DUT TCP SHOULD use 2*MSL upper bound on SYN-segment RTO "
        "(RFC 1122 §4.2.3.1 p96 SHOULD).";
    static constexpr bool             kDeprecated  = false;
    static constexpr int              kTopology    = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup    = ::tc8::BpfGroup::Tcp;

    // The verdict reads the DUT's kernel SYN-RTO plateau (tcpi_rto) — a
    // state introspection the opcode UT exposes (OpQueryTcpInfo) but the
    // standard AUTOSAR testability protocol does not. Declaring
    // kCapTcpStateProbe makes the CLI capability gate honestly SKIP this
    // case on a testability backend (Tier 2 2b#4) instead of failing it.
    // kCapTcpSynSentOpen additionally covers the non-establishing SYN-SENT
    // open (driveSeamSynSentOpen): the testability CONNECT SP requires the
    // handshake to establish and so cannot hold a socket in SYN-SENT, while
    // the opcode non-blocking worker can.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpStateProbe |
        ::tc8::sce::kCapTcpSynSentOpen;

    using Captured = typename SM::CapturedType;
    using Expected = typename SM::ExpectedType;

    static constexpr auto kPollInterval  = std::chrono::milliseconds(2000);
    static constexpr auto kBudget        = std::chrono::milliseconds(90000);

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
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
        // the RTO has a chance to plateau. Body-scoped is sufficient
        // here: the observation always runs to its budget (or an
        // earlier outcome) inside this function, so a deferred hold is
        // unnecessary (unlike _05/_06 which break early on a retx
        // threshold). Installed BEFORE the active open so the first SYN
        // never draws a closed-port RST.
        TesterAutoRstDrop rst_drop(cfg);

        // Active OPEN routed through the backend-agnostic seam, no tester
        // listener — the SYN goes unanswered so the DUT stays in SYN-SENT
        // and retransmits, which is what this case observes.
        auto open_conn = driveSeamSynSentOpen(ctx.dut, cfg, local_port, remote_port);

        // A nullopt open is an unreachable DUT: nothing to probe →
        // ut_handshake_completed stays false → SCXML verdicts
        // fail (dut_active_open_did_not_initiate).
        if (!open_conn) return;
        const ::tc8::sce::DutSocket dut_sock = open_conn->socket;
        c.ut_handshake_completed = true;

        const auto obs = observeRtoCeiling(ctx.dut, dut_sock, kBudget, kPollInterval,
                                           kTwoMslRtoUpperUs);

        c.ut_rto_ceiling         = obs.outcome;
        c.ut_tcpi_p1_valid       = obs.valid;
        c.ut_tcpi_p1_state       = obs.last.state;
        c.ut_tcpi_p1_rto_us      = obs.last.rto_us;
        c.ut_tcpi_p1_retransmits = obs.last.retransmits;
        c.ut_tcpi_p1_unacked     = obs.last.unacked;

        ctx.dut.tcpControl()->closeTcp(dut_sock);
    }

    static void dispatch(Captured& /*c*/, SM& /*sm*/, const ::tc8::CapturedEvent& /*ev*/) {
        // Verdict computed from kernel TCP_INFO snapshot — wire frames
        // not consulted.
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpRetransmissionTo09SM, tcp_retransmission_to_09)
