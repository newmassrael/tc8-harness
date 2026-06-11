#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include <sys/socket.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_basics_10_sm.h"

namespace tc8::sce::cases {

using TcpBasics10SM = ::SCE::Generated::tcp_basics_10::tcp_basics_10;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics10SM>
    : TcpAnyBase<cases::TcpBasics10SM> {
    static constexpr std::string_view kCaseId       = "TCP_BASICS_10";
    static constexpr std::string_view kSpecSection  = "4.8.6.1";
    static constexpr std::string_view kDescription  =
        "TCP MUST send an ACK in response to a FIN received in "
        "FINWAIT-1 or FINWAIT-2 state (RFC 793 §3.2 p23 Terminology)";

    // Spec Test Procedure (v3.0 p281-p300.txt:692), two iterations:
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
    // DUT first — a faithful FINWAIT-2 entry. Phase 1 issues the
    // tester FIN immediately, but Linux's combined-segment optimisation
    // pins the ACK ahead of the FIN on the wire regardless, so phase 1
    // collapses to FINWAIT-2 in practice (see SCXML preamble for
    // commentary). The harness encodes both phases for spec faithfulness;
    // genuine FINWAIT-1 entry would require iptables-driven ACK
    // suppression on the tester side.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // -------- Phase 1: FINWAIT-1 entry --------
        {
            auto listener1 = driveActiveOpenEstablished(
                cfg, iface, cfg.dut.mac,
                /*open_req_id=*/1,
                kBasicsActiveLocalPort  + kTcpBasics10Phase1LocalOffset,
                kBasicsActiveRemotePort + kTcpBasics10Phase1LocalOffset);

            const int tester_fd = listener1.acceptOne();

            // Order: UT close (DUT enters FINWAIT-1, sends FIN) then
            // immediate tester FIN. No pre-FIN delay — phase 2 is
            // where we wait for the tester ACK to settle.
            sendCloseTcpSocketRequest(
                cfg, iface, cfg.dut.mac,
                /*req_id=*/2, /*socket_id=*/1);
            if (tester_fd >= 0) {
                ::shutdown(tester_fd, SHUT_WR);
                ::close(tester_fd);
            }
            std::this_thread::sleep_for(kTcpPilotPhaseGap);
        }

        // -------- Phase 2: FINWAIT-2 entry --------
        {
            const std::uint16_t phase2_local_port  = kBasicsActiveLocalPort  + kTcpBasics10Phase2LocalOffset;
            const std::uint16_t phase2_remote_port = kBasicsActiveRemotePort + kTcpBasics10Phase2LocalOffset;

            auto listener2 = driveActiveOpenEstablished(
                cfg, iface, cfg.dut.mac,
                /*open_req_id=*/3,
                /*local_port=*/phase2_local_port,
                /*remote_port=*/phase2_remote_port);

            const int tester_fd = listener2.acceptOne();

            // Order: UT close → wait 100 ms (DUT receives tester ACK,
            // moves FINWAIT-1 → FINWAIT-2) → tester FIN.
            sendCloseTcpSocketRequest(
                cfg, iface, cfg.dut.mac,
                /*req_id=*/4, /*socket_id=*/2);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (tester_fd >= 0) {
                ::shutdown(tester_fd, SHUT_WR);
                ::close(tester_fd);
            }
            std::this_thread::sleep_for(kTcpPilotPhaseGap);
        }
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_timeout_p1_fin:        return "fail:no_dut_close_fin_phase1";
            case State::Fail_timeout_p1_ack:        return "fail:no_dut_ack_to_tester_fin_phase1";
            case State::Fail_timeout_p2_fin:        return "fail:no_dut_close_fin_phase2";
            case State::Fail_timeout_p2_ack:        return "fail:no_dut_ack_to_tester_fin_phase2";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics10SM, tcp_basics_10)
