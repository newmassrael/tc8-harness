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

#include "tcp_call_abort_03_it2_sm.h"

namespace tc8::sce::cases {

using TcpCallAbort03It2SM =
    ::SCE::Generated::tcp_call_abort_03_it2::tcp_call_abort_03_it2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpCallAbort03It2SM>
    : TcpAnyBase<cases::TcpCallAbort03It2SM> {
    // Drives the DUT's TCP data plane over the Tier-2 seam (driveSeamActiveOpen /
    // shutdownTcpWr / abortTcp), so it is not measurable on a backend without ITcpControl.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl;
    static constexpr std::string_view kCaseId       = "TCP_CALL_ABORT_03_IT2";
    static constexpr std::string_view kDescription  =
        "Iteration 2 of TCP_CALL_ABORT_03: an application ABORT on a DUT in LAST-ACK reports "
        "success and the connection ends up CLOSED, proved by the closed-port RST that a "
        "verify-probe ACK on the killed 4-tuple draws";

    // TC8 §4.8.6.5 — TCP Call Abort (LAST-ACK).
    static constexpr std::uint16_t kPortOffset =
        ::tc8::sce::tcp::kTcpCallAbort03Phase2LocalOffset;

    // AckDrop installed BEFORE handshake (tester outbound pure ACK to DUT FIN must be
    // suppressed). Tester shutdown(WR) drives DUT EST->CW (DUT acks tester FIN). seam
    // shutdownTcpWr drives DUT CW->LAST-ACK (DUT FIN egress; AckDrop blocks tester auto-ACK so
    // DUT stays in LAST-ACK). abort -> RST.
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

        // Tester FIN -> DUT EST->CW. The ACK the DUT emits in response is wire-egress (not
        // affected by tester OUTPUT chain). Tester socket transitions EST->FW1 on shutdown(WR).
        ::shutdown(tester_fd, SHUT_WR);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // shutdownTcpWr -> DUT CW->LAST-ACK. Tester auto-ACK to the DUT FIN is dropped by
        // ack_drop; the DUT stays in LAST-ACK.
        tcp.shutdownTcpWr(open.conn->socket);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // Abort on a LAST-ACK socket -> RST (the abortive close reaches CLOSED). The
        // verify-probe still fires for the closed-port RST as redundant proof.
        cases::abortCallAbort03Socket(tcp, open.conn->socket, tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpCallAbort03It2SM, tcp_call_abort_03_it2)
