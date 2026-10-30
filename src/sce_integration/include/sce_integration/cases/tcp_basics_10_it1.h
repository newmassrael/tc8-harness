#pragma once

#include <cstdint>
#include <string_view>
#include <unistd.h>

#include "sce_integration/case_iteration.h"
#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_seam_time_wait_prelude.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/tcp_pilot_common.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"

#include "tcp_basics_10_it1_sm.h"

namespace tc8::sce::cases {

using TcpBasics10It1SM = ::SCE::Generated::tcp_basics_10_it1::tcp_basics_10_it1;

}  // namespace tc8::sce::cases

// The TC8 case is the ordered set of its two iterations (case_iteration.h); declared here,
// once, beside the first.
TC8_REGISTER_ITERATED_CASE(
    "TCP_BASICS_10",
    "A DUT that has closed its side answers the tester's FIN with an acknowledgement of that "
    "FIN, whether it is still waiting for the ACK of its own FIN (FINWAIT-1) or has had it "
    "acknowledged (FINWAIT-2) (RFC 793 §3.2 p23)")

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics10It1SM>
    : TcpAnyBase<cases::TcpBasics10It1SM> {
    // Drives the DUT's TCP data plane over the Tier-2 seam (driveSeamActiveOpen /
    // driveSeamCloseToClosing), so it is not measurable on a backend without ITcpControl.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl;
    static constexpr std::string_view kCaseId       = "TCP_BASICS_10_IT1";
    static constexpr std::string_view kDescription  =
        "Iteration 1 of TCP_BASICS_10: a FIN from the tester, arriving while the DUT is "
        "still in FINWAIT-1, is answered with an acknowledgement of that FIN";

    // Handshake -> DUT close -> tester FIN -> DUT ACK, observed as DUT FIN+ACK (close
    // marker) then DUT pure ACK (response to the tester FIN). The SCXML enforces the
    // FIN-then-ACK order so the handshake third-leg ACK cannot satisfy the post-FIN ACK
    // guard.
    //
    // The tester's ACK of the DUT's FIN is dropped (TesterAutoAckDrop), so the DUT holds
    // FINWAIT-1, and the tester FIN is injected with an ACK field short of the DUT's FIN
    // (driveSeamCloseToClosing). The DUT's ACK of THAT FIN is graded: its ack number is the
    // FIN's sequence number plus one (captured.expected_ack_num).
    // Migrated onto the Tier-2 DUT-control seam: the active open runs through
    // `driveSeamActiveOpen` and the DUT close through `closeTcp`, so the case runs
    // unchanged on whichever backend `--dut-control` selected (opcode UT or AUTOSAR
    // testability). The tester-side accept that drives the FIN stays case-owned harness
    // infrastructure; the DUT socket id is threaded from the connection (no hardcoded id).
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        using namespace ::tc8::sce::tcp;

        // The tester kernel's ACK of the DUT's FIN is dropped for the whole stimulus, so the
        // DUT stays in FINWAIT-1, and the tester's FIN is injected raw with an ACK field
        // that does not cover the DUT's FIN (driveSeamCloseToClosing): the FIN the DUT must
        // acknowledge arrives while it is in FINWAIT-1, which it leaves for CLOSING as it
        // answers. A kernel FIN cannot do this, because it would acknowledge the DUT's FIN
        // and move the DUT straight to TIME-WAIT.
        TesterAutoAckDrop ack_drop(cfg);
        (void)ack_drop;
        constexpr std::uint16_t local_port  = kBasicsActiveLocalPort  + kTcpBasics10Phase1LocalOffset;
        constexpr std::uint16_t remote_port = kBasicsActiveRemotePort + kTcpBasics10Phase1LocalOffset;
        auto open = driveSeamActiveOpen(ctx.dut, cfg, local_port, remote_port);

        const int tester_fd = acceptPreambleConnection(open);
        if (open.conn && tester_fd >= 0) {
            const auto info = driveSeamCloseToClosing(ctx.dut, cfg, ctx.iface, tester_fd,
                                                      open.conn->socket, local_port,
                                                      remote_port);
            if (info.ok) {
                // The ACK of that FIN: its sequence number plus one.
                c.expected_ack_num = info.tester_seq_post_fin;
                silentlyCloseTesterFd(tester_fd);
            }
        } else if (tester_fd >= 0) {
            ::close(tester_fd);
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics10It1SM, tcp_basics_10_it1)
