#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "sce_integration/case_iteration.h"
#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_call_abort_03_common.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_seam_time_wait_prelude.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"

#include "tcp_call_abort_03_it1_sm.h"

namespace tc8::sce::cases {

using TcpCallAbort03It1SM =
    ::SCE::Generated::tcp_call_abort_03_it1::tcp_call_abort_03_it1;

}  // namespace tc8::sce::cases

// The TC8 case is the ordered set of its three iterations (case_iteration.h); declared here,
// once, beside the first.
TC8_REGISTER_ITERATED_CASE(
    "TCP_CALL_ABORT_03",
    "A DUT whose application aborts a connection that is in CLOSING, in LAST-ACK or in "
    "TIME-WAIT reports success to that application and ends up CLOSED (RFC 793 §3.9 p62 "
    "Event Processing)")

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpCallAbort03It1SM>
    : TcpAnyBase<cases::TcpCallAbort03It1SM> {
    // Drives the DUT's TCP data plane over the Tier-2 seam (driveSeamActiveOpen /
    // shutdownTcpWr / abortTcp), so it is not measurable on a backend without ITcpControl.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl;
    static constexpr std::string_view kCaseId       = "TCP_CALL_ABORT_03_IT1";
    static constexpr std::string_view kDescription  =
        "Iteration 1 of TCP_CALL_ABORT_03: an application ABORT on a DUT in CLOSING reports "
        "success and the connection ends up CLOSED, proved by the closed-port RST that a "
        "verify-probe ACK on the killed 4-tuple draws";

    // TC8 §4.8.6.5 — TCP Call Abort (CLOSING).
    static constexpr std::uint16_t kPortOffset =
        ::tc8::sce::tcp::kTcpCallAbort03Phase1LocalOffset;

    // The DUT sends its FIN through shutdownTcpWr, not closeTcp, and the CLOSING core
    // (driveToClosingState, caller-managed AckDrop scope) answers it with a FIN+ACK that does
    // not ack it, so the DUT is in CLOSING with its socket still held. The ABORT then reaches a
    // connection the DUT has, which is what the step asks. A closeTcp here would release the
    // socket first: the Upper Tester then refuses the ABORT as an unknown socket, so the
    // abort-in-CLOSING was never performed (measured on single-pc 2026-10-28, status 0x05).
    // The verify-probe proves CLOSED. silentlyCloseTesterFd disposes the tester fd; the AckDrop
    // dtor at scope end removes the rule.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffset;

        // Verify-probe ACK on entry to verify_rst: it arrives after the prelude+abort settle
        // window.
        cases::scheduleCallAbort03VerifyProbe(
            ctx.scheduler, static_cast<int>(State::Listening_verify_rst), cfg, ctx.iface,
            kPortOffset);

        TesterAutoAckDrop ack_drop(cfg);
        (void)ack_drop;

        auto open = driveSeamActiveOpen(ctx.dut, cfg, local_port, remote_port);
        const int tester_fd = acceptPreambleConnection(open);
        if (tester_fd < 0) return;
        if (!open.conn) return;

        auto& tcp = seamTcpControl(ctx.dut);
        const ::tc8::sce::DutSocket sock = open.conn->socket;
        const auto info = driveToClosingState(
            cfg, ctx.iface, cfg.dut.mac, tester_fd, local_port, remote_port,
            [&tcp, sock]() { tcp.shutdownTcpWr(sock); });
        if (!info.ok) return;
        // DUT now in CLOSING, its socket still open.

        cases::abortCallAbort03Socket(tcp, sock, tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpCallAbort03It1SM, tcp_call_abort_03_it1)
