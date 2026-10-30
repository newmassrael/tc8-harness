#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include <sys/socket.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_call_abort_03_common.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"

#include "tcp_call_abort_03_it3_sm.h"

namespace tc8::sce::cases {

using TcpCallAbort03It3SM =
    ::SCE::Generated::tcp_call_abort_03_it3::tcp_call_abort_03_it3;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpCallAbort03It3SM>
    : TcpAnyBase<cases::TcpCallAbort03It3SM> {
    // Drives the DUT's TCP data plane over the Tier-2 seam (driveSeamActiveOpen /
    // shutdownTcpWr / abortTcp), so it is not measurable on a backend without ITcpControl.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl;
    static constexpr std::string_view kCaseId       = "TCP_CALL_ABORT_03_IT3";
    static constexpr std::string_view kDescription  =
        "Iteration 3 of TCP_CALL_ABORT_03: an application ABORT on a DUT in TIME-WAIT reports "
        "success and the connection ends up CLOSED, proved by the closed-port RST that a "
        "verify-probe ACK on the killed 4-tuple draws";

    // TC8 §4.8.6.5 — TCP Call Abort (TIME-WAIT).
    static constexpr std::uint16_t kPortOffset =
        ::tc8::sce::tcp::kTcpCallAbort03Phase3LocalOffset;

    // seam shutdownTcpWr -> DUT FIN -> tester auto-ACK (NO AckDrop) drives DUT FW1->FW2.
    // Tester shutdown(WR) -> tester FIN -> DUT FW2->TW (DUT pure ACK egress). abort on the TW
    // socket emits no wire RST (a TIME-WAIT abort is silent on the wire), so the verify-probe
    // ACK is the wire-observable pass criterion.
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

        auto open = driveSeamActiveOpen(ctx.dut, cfg, local_port, remote_port);
        const int tester_fd = acceptPreambleConnection(open);
        if (tester_fd < 0) return;
        if (!open.conn) return;

        auto& tcp = seamTcpControl(ctx.dut);

        // shutdown(WR) - DUT FIN. Tester kernel auto-ACK drives DUT FW1->FW2. NO AckDrop here:
        // the auto-ACK is wanted.
        tcp.shutdownTcpWr(open.conn->socket);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // Tester FIN -> DUT FW2->TIME-WAIT. DUT emits pure ACK; tester sees it and transitions
        // tester FW1 (after the earlier shutdown WR EST->FW1) -> CLOSED. Wait for the DUT ACK
        // egress before issuing abort so the wire signature of TW entry is captured before
        // abort fires.
        ::shutdown(tester_fd, SHUT_WR);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // Abort on the TIME-WAIT socket -> CLOSED (the DUT force-terminates the TIME-WAIT
        // residual internally). A TIME-WAIT abort emits no wire RST, so the verify-probe ACK is
        // the load-bearing CLOSED-proof for this iteration.
        cases::abortCallAbort03Socket(tcp, open.conn->socket, tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpCallAbort03It3SM, tcp_call_abort_03_it3)
