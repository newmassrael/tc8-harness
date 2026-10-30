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
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"

#include "tcp_basics_08_it3_sm.h"

namespace tc8::sce::cases {

using TcpBasics08It3SM = ::SCE::Generated::tcp_basics_08_it3::tcp_basics_08_it3;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics08It3SM>
    : TcpAnyBase<cases::TcpBasics08It3SM> {
    // Drives the DUT's TCP data plane over the Tier-2 seam (driveSeamActiveOpen /
    // closeTcp), so it is not measurable on a backend without ITcpControl.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl;
    static constexpr std::string_view kCaseId       = "TCP_BASICS_08_IT3";
    static constexpr std::string_view kDescription  =
        "Iteration 2 of TCP_BASICS_08: a CLOSE call on a DUT in CLOSE-WAIT makes its TCP "
        "emit a FIN";

    // Handshake -> tester FIN -> DUT auto-ACK (now CLOSE-WAIT) -> UT close -> DUT FIN.
    //
    // The tester FIN is issued by accept()'ing the queued connection on the tester listener
    // and then shutdown(SHUT_WR)'ing the connected fd; without the accept() the kernel
    // completes the handshake but provides no userland handle for emitting an
    // application-driven FIN at a controlled point in the procedure.
    //
    // Runs through the Tier-2 DUT-control seam: the active open through
    // `driveSeamActiveOpen` (ITcpControl) and the DUT close through `closeTcp`, so the case
    // runs unchanged on whichever backend `--dut-control` selected (opcode UT or AUTOSAR
    // testability). The DUT-assigned socket id is threaded from the open's connection (no
    // hardcoded id). The tester-side accept/shutdown stays case-owned harness
    // infrastructure.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        using namespace ::tc8::sce::tcp;

        auto open = driveSeamActiveOpen(
            ctx.dut, cfg,
            kBasicsActiveLocalPort  + kTcpBasics08Phase2LocalOffset,
            kBasicsActiveRemotePort + kTcpBasics08Phase2LocalOffset);

        // Accept the queued tester-side connection so we have a
        // userland handle for the FIN emission. 1 s timeout absorbs
        // worker-netns scheduling jitter; if accept times out the
        // SCXML lands on fail_timeout (no DUT FIN observed)
        // — a clean diagnostic that points at the helper, not the
        // DUT.
        const int tester_fd = acceptPreambleConnection(open);
        if (tester_fd >= 0) {
            ::shutdown(tester_fd, SHUT_WR);
            // Brief grace so the DUT kernel processes the FIN and
            // emits its CLOSE-WAIT auto-ACK before the CLOSE
            // triggers the spec-required DUT FIN. Without this the
            // close path can race the auto-ACK out and produce a
            // single FIN+ACK from DUT that batches both — still
            // spec-conformant, but using a lighter pass guard.
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (open.conn) {
            ctx.dut.tcpControl()->closeTcp(open.conn->socket);
        }

        if (tester_fd >= 0) ::close(tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics08It3SM, tcp_basics_08_it3)
