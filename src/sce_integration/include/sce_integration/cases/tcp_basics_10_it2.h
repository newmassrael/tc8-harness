#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include <sys/socket.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/tcp_pilot_common.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"

#include "tcp_basics_10_it2_sm.h"

namespace tc8::sce::cases {

using TcpBasics10It2SM = ::SCE::Generated::tcp_basics_10_it2::tcp_basics_10_it2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics10It2SM>
    : TcpAnyBase<cases::TcpBasics10It2SM> {
    // Drives the DUT's TCP data plane over the Tier-2 seam (driveSeamActiveOpen /
    // closeTcp), so it is not measurable on a backend without ITcpControl.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl;
    static constexpr std::string_view kCaseId       = "TCP_BASICS_10_IT2";
    static constexpr std::string_view kDescription  =
        "Iteration 2 of TCP_BASICS_10: a FIN from the tester, arriving after the DUT's own "
        "FIN has been acknowledged and it sits in FINWAIT-2, is answered with an "
        "acknowledgement of that FIN";

    // Handshake -> DUT close -> 100 ms -> tester FIN -> DUT ACK, observed as DUT FIN+ACK
    // (close marker) then DUT pure ACK (response to the tester FIN). The SCXML enforces the
    // FIN-then-ACK order so the handshake third-leg ACK cannot satisfy the post-FIN ACK
    // guard.
    //
    // The 100 ms grace between the DUT close and the tester FIN lets the tester kernel's
    // auto-ACK of the DUT's FIN reach the DUT first, a faithful FINWAIT-2 entry. The DUT's
    // ACK of the tester FIN is graded: its ack number is the FIN's sequence number plus one
    // (captured.expected_ack_num).
    // Migrated onto the Tier-2 DUT-control seam: the active open runs through
    // `driveSeamActiveOpen` and the DUT close through `closeTcp`, so the case runs
    // unchanged on whichever backend `--dut-control` selected (opcode UT or AUTOSAR
    // testability). The tester-side accept/shutdown that drives the FIN stays case-owned
    // harness infrastructure; the DUT socket id is threaded from the connection (no
    // hardcoded id).
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        using namespace ::tc8::sce::tcp;

        auto open = driveSeamActiveOpen(
            ctx.dut, cfg,
            kBasicsActiveLocalPort  + kTcpBasics10Phase2LocalOffset,
            kBasicsActiveRemotePort + kTcpBasics10Phase2LocalOffset);

        const int tester_fd = acceptPreambleConnection(open);

        // Order: DUT close -> wait 100 ms (DUT receives tester ACK,
        // moves FINWAIT-1 -> FINWAIT-2) -> tester FIN.
        if (open.conn) ctx.dut.tcpControl()->closeTcp(open.conn->socket);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (tester_fd >= 0) {
            // The kernel FIN takes the tester's next sequence number, so its
            // ACK carries that plus one.
            if (const auto seq = queryTcpSeqRange(tester_fd)) {
                c.expected_ack_num = seq->snd_nxt + 1U;
            }
            ::shutdown(tester_fd, SHUT_WR);
            ::close(tester_fd);
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics10It2SM, tcp_basics_10_it2)
