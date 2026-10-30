#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_iteration.h"
#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"

#include "tcp_basics_08_it1_sm.h"

namespace tc8::sce::cases {

using TcpBasics08It1SM = ::SCE::Generated::tcp_basics_08_it1::tcp_basics_08_it1;

}  // namespace tc8::sce::cases

// The TC8 case is the ordered set of its two iterations (case_iteration.h); declared here,
// once, beside the first.
// The spec numbers this case's iterations 1 and 3 (there is no 2), and an iteration is named
// by the number the spec gives it.
TC8_REGISTER_ITERATED_CASE_NUMBERED(
    "TCP_BASICS_08",
    "A CLOSE call on a DUT whose connection is in ESTABLISHED or CLOSE-WAIT makes the DUT's "
    "TCP emit a FIN (RFC 793 §3.2 p23 Terminology)",
    "13")

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics08It1SM>
    : TcpAnyBase<cases::TcpBasics08It1SM> {
    // Drives the DUT's TCP data plane over the Tier-2 seam (driveSeamActiveOpen /
    // closeTcp), so it is not measurable on a backend without ITcpControl.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl;
    static constexpr std::string_view kCaseId       = "TCP_BASICS_08_IT1";
    static constexpr std::string_view kDescription  =
        "Iteration 1 of TCP_BASICS_08: a CLOSE call on a DUT in ESTABLISHED makes its TCP "
        "emit a FIN";

    // Handshake -> UT close -> DUT FIN.
    //
    // Runs through the Tier-2 DUT-control seam: the active open through
    // `driveSeamActiveOpen` (ITcpControl) and the DUT close through `closeTcp`, so the case
    // runs unchanged on whichever backend `--dut-control` selected (opcode UT or AUTOSAR
    // testability). The verdict rests on the FIN that `closeTcp` produces. The DUT-assigned
    // socket id is threaded from the open's connection (no hardcoded id).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        using namespace ::tc8::sce::tcp;

        auto open = driveSeamActiveOpen(
            ctx.dut, cfg,
            kBasicsActiveLocalPort  + kTcpBasics08Phase1LocalOffset,
            kBasicsActiveRemotePort + kTcpBasics08Phase1LocalOffset);

        // CLOSE on the DUT side closes the connected socket; a graceful
        // close of a connected SOCK_STREAM emits FIN — the observable
        // artifact of the spec-mandated CLOSE call. The matching SCXML
        // pass guard's `(flags & FIN)` conjunct fires on this segment.
        if (open.conn) {
            ctx.dut.tcpControl()->closeTcp(open.conn->socket);
        }
    }   // open.listener destructed: its queued accepted connection (never
        // accept()'d) is RST'd by the kernel — by design, a FIN_WAIT_2 →
        // CLOSED transition for the post-DUT-FIN remnant.
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics08It1SM, tcp_basics_08_it1)
