#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include <sys/socket.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_seam_time_wait_prelude.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/tcp_pilot_common.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"

#include "tcp_basics_10_sm.h"

namespace tc8::sce::cases {

using TcpBasics10SM = ::SCE::Generated::tcp_basics_10::tcp_basics_10;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics10SM>
    : TcpAnyBase<cases::TcpBasics10SM> {
    // Drives the DUT's TCP data plane over the Tier-2 seam (driveSeamListen /
    // closeTcp), so it is not measurable on a backend without ITcpControl.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl;
    static constexpr std::string_view kCaseId       = "TCP_BASICS_10";
    static constexpr std::string_view kDescription  =
        "TCP MUST send an ACK in response to a FIN received in "
        "FINWAIT-1 or FINWAIT-2 state (RFC 793 §3.2 p23 Terminology)";

    // Case shape — two iterations:
    //   * Phase 1 — <wst>=FINWAIT-1:
    //       handshake → UT close → tester FIN → DUT ACK.
    //   * Phase 2 — <wst>=FINWAIT-2:
    //       handshake → UT close → wait → tester FIN → DUT ACK.
    //
    // Both phases drive the same observable sequence: DUT FIN+ACK
    // (close marker), then DUT pure ACK (response to tester FIN). The
    // SCXML enforces FIN-then-ACK ordering so the handshake third-leg
    // ACK cannot accidentally satisfy the post-FIN ACK guard.
    //
    // Phase 2 inserts a 100 ms grace between UT close and the tester
    // FIN so the tester-kernel's auto-ACK of the DUT's FIN reaches the
    // DUT first — a faithful FINWAIT-2 entry. Phase 1 holds the DUT in
    // FINWAIT-1: the tester's ACK of the DUT's FIN is dropped
    // (TesterAutoAckDrop) and the tester FIN is injected with an ACK
    // field short of the DUT's FIN (driveSeamCloseToClosing). Each phase
    // grades the DUT's ACK of THAT FIN: its ack number is the FIN's
    // sequence number plus one (captured.expected_ack_num /
    // expected_ack_num_phase2).
    // Migrated onto the Tier-2 DUT-control seam: both phases' active opens
    // run through `driveSeamActiveOpen` and both DUT closes through `closeTcp`,
    // so the case runs unchanged on whichever backend `--dut-control` selected
    // (opcode UT or AUTOSAR testability). The tester-side accept/shutdown that
    // drives the FIN stays case-owned harness infrastructure; the DUT socket id
    // is threaded from each phase's connection (no hardcoded id).
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        using namespace ::tc8::sce::tcp;

        // -------- Phase 1: FINWAIT-1 entry --------
        {
            // The tester kernel's ACK of the DUT's FIN is dropped for the whole
            // phase, so the DUT stays in FINWAIT-1, and the tester's FIN is
            // injected raw with an ACK field that does not cover the DUT's FIN
            // (driveSeamCloseToClosing): the FIN the DUT must acknowledge
            // arrives while it is in FINWAIT-1, which it leaves for CLOSING as
            // it answers. A kernel FIN cannot do this, because it would
            // acknowledge the DUT's FIN and move the DUT straight to TIME-WAIT.
            TesterAutoAckDrop ack_drop(cfg);
            (void)ack_drop;
            constexpr std::uint16_t local_port  = kBasicsActiveLocalPort  + kTcpBasics10Phase1LocalOffset;
            constexpr std::uint16_t remote_port = kBasicsActiveRemotePort + kTcpBasics10Phase1LocalOffset;
            auto open1 = driveSeamActiveOpen(ctx.dut, cfg, local_port, remote_port);

            const int tester_fd = acceptPreambleConnection(open1);
            if (open1.conn && tester_fd >= 0) {
                const auto info = driveSeamCloseToClosing(ctx.dut, cfg, ctx.iface, tester_fd,
                                                          open1.conn->socket, local_port,
                                                          remote_port);
                if (info.ok) {
                    // The ACK of that FIN: its sequence number plus one.
                    c.expected_ack_num = info.tester_seq_post_fin;
                    silentlyCloseTesterFd(tester_fd);
                }
            } else if (tester_fd >= 0) {
                ::close(tester_fd);
            }
            std::this_thread::sleep_for(kTcpPilotPhaseGap);
        }

        // -------- Phase 2: FINWAIT-2 entry --------
        {
            auto open2 = driveSeamActiveOpen(
                ctx.dut, cfg,
                kBasicsActiveLocalPort  + kTcpBasics10Phase2LocalOffset,
                kBasicsActiveRemotePort + kTcpBasics10Phase2LocalOffset);

            const int tester_fd = acceptPreambleConnection(open2);

            // Order: DUT close → wait 100 ms (DUT receives tester ACK,
            // moves FINWAIT-1 → FINWAIT-2) → tester FIN.
            if (open2.conn) ctx.dut.tcpControl()->closeTcp(open2.conn->socket);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (tester_fd >= 0) {
                // The kernel FIN takes the tester's next sequence number, so its
                // ACK carries that plus one.
                if (const auto seq = queryTcpSeqRange(tester_fd)) {
                    c.expected_ack_num_phase2 = seq->snd_nxt + 1U;
                }
                ::shutdown(tester_fd, SHUT_WR);
                ::close(tester_fd);
            }
            std::this_thread::sleep_for(kTcpPilotPhaseGap);
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics10SM, tcp_basics_10)
