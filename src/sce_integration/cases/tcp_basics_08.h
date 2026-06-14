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

#include "tcp_basics_08_sm.h"

namespace tc8::sce::cases {

using TcpBasics08SM = ::SCE::Generated::tcp_basics_08::tcp_basics_08;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics08SM>
    : TcpAnyBase<cases::TcpBasics08SM> {
    static constexpr std::string_view kCaseId       = "TCP_BASICS_08";
    static constexpr std::string_view kSpecSection  = "4.8.6.1";
    static constexpr std::string_view kDescription  =
        "TCP MUST send a FIN on a CLOSE call in ESTABLISHED or "
        "CLOSE-WAIT state (RFC 793 §3.2 p23 Terminology)";

    // Spec Test Procedure (v3.0 p281-p300.txt:623), two iterations:
    //   * Phase 1 — <wst>=ESTABLISHED:
    //       handshake → UT close → DUT FIN.
    //   * Phase 2 — <wst>=CLOSE-WAIT:
    //       handshake → tester FIN → DUT auto-ACK → UT close → DUT FIN.
    //
    // Phase 2 issues the tester FIN by accept()'ing the queued
    // connection on the tester listener and then shutdown(SHUT_WR)'ing
    // the connected fd; without the accept() the kernel completes the
    // handshake but provides no userland handle for emitting an
    // application-driven FIN at a controlled point in the procedure.
    //
    // The two phases use distinct port quads (49500↔23456 vs
    // 49501↔23457) so the SCXML phase-1 → phase-2 transition is not at
    // risk of matching a phase-1 teardown FIN late, and phase-2's
    // listener cannot accidentally pick up a stray retransmit from the
    // earlier connection.
    //
    // Migrated onto the Tier-2 DUT-control seam: both active opens run
    // through `driveSeamActiveOpen` (ITcpControl) and both DUT closes
    // through `closeTcp`, so the case runs unchanged on whichever backend
    // `--dut-control` selected (opcode UT or AUTOSAR testability). This is
    // the second TCP case on the seam after the BASICS_06 pilot, and the
    // first whose verdict rests on the FIN that `closeTcp` produces — the
    // pilot only asserted the SYN from the open. The DUT-assigned socket id
    // is threaded from each open's connection (no hardcoded id): phase 1's
    // socket is closed inside phase 1; phase 2 opens a fresh one. The
    // tester-side accept/shutdown stays case-owned harness infrastructure.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view /*iface*/,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // -------- Phase 1: ESTABLISHED → CLOSE → FIN --------
        {
            auto open1 = driveSeamActiveOpen(
                dut, cfg,
                kBasicsActiveLocalPort  + kTcpBasics08Phase1LocalOffset,
                kBasicsActiveRemotePort + kTcpBasics08Phase1LocalOffset);

            // CLOSE on the DUT side closes the connected socket; a graceful
            // close of a connected SOCK_STREAM emits FIN — the observable
            // artifact of the spec-mandated CLOSE call. The matching SCXML
            // pass guard's `(flags & FIN)` conjunct fires on this segment.
            if (open1.conn) {
                dut.tcpControl()->closeTcp(open1.conn->socket);
            }
            std::this_thread::sleep_for(kTcpPilotPhaseGap);
        }  // open1.listener destructed: its queued accepted connection
           // (never accept()'d) is RST'd by the kernel — by design,
           // a FIN_WAIT_2 → CLOSED transition for the post-DUT-FIN
           // remnant. Distinct phase 2 ports keep this RST out of
           // the phase 2 matching window.

        // -------- Phase 2: CLOSE-WAIT → CLOSE → FIN --------
        {
            auto open2 = driveSeamActiveOpen(
                dut, cfg,
                kBasicsActiveLocalPort  + kTcpBasics08Phase2LocalOffset,
                kBasicsActiveRemotePort + kTcpBasics08Phase2LocalOffset);

            // Accept the queued tester-side connection so we have a
            // userland handle for the FIN emission. 1 s timeout absorbs
            // worker-netns scheduling jitter; if accept times out the
            // SCXML lands on fail_timeout_phase2 (no DUT FIN observed)
            // — a clean diagnostic that points at the helper, not the
            // DUT.
            const int tester_fd = open2.listener.acceptOne();
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

            if (open2.conn) {
                dut.tcpControl()->closeTcp(open2.conn->socket);
            }

            if (tester_fd >= 0) ::close(tester_fd);
            std::this_thread::sleep_for(kTcpPilotPhaseGap);
        }
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                   return "pass";
            case State::Fail_timeout_phase1:    return "fail:no_dut_fin_from_established";
            case State::Fail_timeout_phase2:    return "fail:no_dut_fin_from_close_wait";
            default:                            return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics08SM, tcp_basics_08)
