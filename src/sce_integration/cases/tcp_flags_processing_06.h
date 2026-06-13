#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_time_wait_prelude.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_processing_06_sm.h"

namespace tc8::sce::cases {

using TcpFlagsProcessing06SM =
    ::SCE::Generated::tcp_flags_processing_06::tcp_flags_processing_06;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsProcessing06SM>
    : TcpAnyBase<cases::TcpFlagsProcessing06SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_PROCESSING_06";
    static constexpr std::string_view kSpecSection  = "4.8.6.7";
    static constexpr std::string_view kDescription  =
        "TCP in TIME-WAIT state MUST acknowledge a retransmitted FIN "
        "and restart the 2*MSL time-out (RFC 793 §3.9 p73 Event "
        "Processing)";

    // Linux MSL derivation: TCP_TIMEWAIT_LEN = 60 s = 2*MSL → MSL =
    // 30 s. Spec's 1.5*MSL = 45 s. The first replay FIN restarts
    // DUT's TW timer per RFC 793 §3.9, so at t = 45 s post-restart
    // the timer (60 s budget) is still live and DUT must ACK the
    // second replay FIN.
    static constexpr auto kHalfMslWait = std::chrono::seconds(45);

    // Migrated onto the Tier-2 DUT-control seam: the FIN-WAIT-2
    // TIME-WAIT prelude runs through driveSeamTimeWaitFw2 (active OPEN
    // via the seam, DUT CLOSE via closeTcp), so the case runs unchanged
    // on whichever backend --dut-control selected. The two replay FINs,
    // the shared_ptr TesterAutoRstDrop, and the 1.5*MSL wall-time wait
    // stay tester-side / SCXML-driven.
    //
    // Synchronous prelude (driveSeamTimeWaitFw2) drives DUT into
    // TIME-WAIT on (kBasicsActiveLocalPort + 51, kBasicsActiveRemotePort
    // + 51) — distinct from the §4.8 TIME-WAIT cluster's default +0
    // quad to dodge cross-case TIME-WAIT residue collisions
    // (BASICS_11/12/13/14, UNACCEPTABLE_13, FLAGS_INVALID_14 all use
    // the default).
    //
    // Replay phasing splits the spec's two-FIN sequence into
    // state-entry observers chained with a wall-time schedule:
    //   1. scheduleAfterStateEntry(Listening_first_replay_ack):
    //      raw-inject the first replay FIN as soon as SCXML lands
    //      on the post-tester-fin_ack state. Same wire shape as
    //      BASICS_13's single replay FIN.
    //   2. scheduleAfterStateEntry(Listening_second_replay_ack):
    //      enqueue scheduler.schedule(kHalfMslWait, …) so the second
    //      replay FIN lands 45 s of wall-time later. Splitting
    //      "state-entry registration → wall-time schedule" keeps the
    //      trait independent of the SCXML's deadline value (50 s)
    //      — same pattern as BASICS_11/12.
    //
    // TesterAutoRstDrop held in a shared_ptr captured by value in
    // both schedule lambdas — load-bearing for the wall-time wait.
    // Without it, the DUT pure ACK to the first replay FIN arrives
    // at the tester on a 4-tuple with no kernel socket
    // (driveSeamTimeWaitFw2 closes the tester fd at prelude end);
    // the tester kernel's `tcp_v4_send_reset` would emit RST per
    // RFC 793 §3.4, the RST would reach DUT, and Linux's
    // `tcp_timewait_state_process` would `goto kill` the TW socket
    // immediately. The 45 s wait would then expire onto a CLOSED
    // 4-tuple and the second replay FIN would draw a closed-port
    // RST (verified empirically via pcap, 2026-04-26). The
    // shared_ptr keeps the iptables rule alive until both lambdas
    // (and the inner schedule) finish — covers DUT-ACK-to-RST race
    // for both replay rounds.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        constexpr std::uint16_t kPortOffset = 51U;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffset;

        const auto info = driveSeamTimeWaitFw2(
            dut, cfg, local_port, remote_port);
        if (!info.ok) return;

        auto rst_drop = std::make_shared<TesterAutoRstDrop>(cfg);

        std::string                 iface_copy(iface);
        ::tc8::TestConfig           cfg_copy   = cfg;
        std::array<std::uint8_t, 6> dut_mac    = cfg.dut.mac;
        const std::uint32_t         tester_seq = info.tester_seq_post_fin;
        const std::uint32_t         tester_ack = info.tester_ack_post_fin;

        auto inject_replay_fin =
            [iface_copy, cfg_copy, dut_mac,
             local_port, remote_port, tester_seq, tester_ack]() {
                ::tc8::stimulus::TcpSegmentSpec replay{};
                replay.src_port = remote_port;
                replay.dst_port = local_port;
                replay.seq_num  = tester_seq;
                replay.ack_num  = tester_ack;
                replay.flags    = ::tc8::stimulus::kTcpFlagFin
                                | ::tc8::stimulus::kTcpFlagAck;
                emitTcpFrame(cfg_copy, iface_copy, dut_mac, replay,
                             /*initial_wait=*/std::chrono::milliseconds(0));
            };

        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_first_replay_ack),
            [inject_replay_fin, rst_drop]() {
                (void)rst_drop;
                inject_replay_fin();
            });

        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_second_replay_ack),
            [&scheduler, inject_replay_fin, rst_drop]() {
                scheduler.schedule(
                    kHalfMslWait,
                    [inject_replay_fin, rst_drop]() {
                        (void)rst_drop;
                        inject_replay_fin();
                    });
            });
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                           return "pass";
            case State::Fail_no_handshake_ack:          return "fail:no_dut_handshake_ack";
            case State::Fail_no_dut_fin:                return "fail:no_dut_close_fin";
            case State::Fail_no_tester_fin_ack:         return "fail:no_dut_ack_to_tester_fin";
            case State::Fail_no_first_replay_ack:       return "fail:no_dut_ack_to_first_replay_fin_in_time_wait";
            case State::Fail_no_second_replay_ack:      return "fail:no_dut_ack_to_second_replay_fin_after_1_5_msl";
            default:                                    return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing06SM, tcp_flags_processing_06)
