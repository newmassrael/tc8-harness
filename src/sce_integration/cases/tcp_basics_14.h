#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_basics_14_sm.h"

namespace tc8::sce::cases {

using TcpBasics14SM = ::SCE::Generated::tcp_basics_14::tcp_basics_14;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics14SM>
    : TcpAnyBase<cases::TcpBasics14SM> {
    static constexpr std::string_view kCaseId       = "TCP_BASICS_14";
    static constexpr std::string_view kSpecSection  = "4.8.6.1";
    static constexpr std::string_view kDescription  =
        "TCP MUST NOT move on to CLOSED state from TIME-WAIT state "
        "before 2*MSL time expires, where TIME-WAIT is reached "
        "through CLOSING (NEGATIVE RFC 793 §3.2 p23 Terminology)";

    // CLOSING-path prelude: active-OPEN handshake → tester accepts
    // → driveCloseToTimeWaitClosing (UT close + ack-suppressed
    // raw-inject FIN/ACK pair → DUT FIN-WAIT-1 → CLOSING →
    // TIME-WAIT → silent tester-side close). Replay phase fires
    // immediately when the SCXML lands on Listening_replay_ack
    // (state-entry observer); DUT in TIME-WAIT replies pure ACK,
    // satisfying the within-2*MSL spec step.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.dut.mac,
            /*open_req_id=*/1,
            kBasicsActiveLocalPort  + kTcpBasics14LocalOffset,
            kBasicsActiveRemotePort + kTcpBasics14LocalOffset);
        const int tester_fd = listener.acceptOne();
        if (tester_fd < 0) return;

        const auto info = driveCloseToTimeWaitClosing(
            cfg, iface, cfg.dut.mac, tester_fd,
            /*close_req_id=*/2, /*socket_id=*/1,
            kBasicsActiveLocalPort  + kTcpBasics14LocalOffset,
            kBasicsActiveRemotePort + kTcpBasics14LocalOffset);
        if (!info.ok) return;

        std::string                 iface_copy(iface);
        ::tc8::TestConfig           cfg_copy   = cfg;
        std::array<std::uint8_t, 6> dut_mac    = cfg.dut.mac;
        const std::uint32_t         tester_seq = info.tester_seq_post_fin;
        const std::uint32_t         tester_ack = info.tester_ack_post_fin;
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_replay_ack),
            [iface_copy, cfg_copy, dut_mac, tester_seq, tester_ack]() {
                ::tc8::stimulus::TcpSegmentSpec replay{};
                replay.src_port = kBasicsActiveRemotePort + kTcpBasics14LocalOffset;
                replay.dst_port = kBasicsActiveLocalPort  + kTcpBasics14LocalOffset;
                replay.seq_num  = tester_seq;
                replay.ack_num  = tester_ack;
                replay.flags    = ::tc8::stimulus::kTcpFlagFin
                                | ::tc8::stimulus::kTcpFlagAck;
                emitTcpFrame(cfg_copy, iface_copy, dut_mac, replay,
                             /*initial_wait=*/std::chrono::milliseconds(0));
            });
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_no_handshake_ack:      return "fail:no_dut_handshake_ack";
            case State::Fail_no_close_fin:          return "fail:no_dut_close_fin";
            case State::Fail_no_closing_ack:        return "fail:no_dut_ack_in_closing_transition";
            case State::Fail_no_replay_ack:         return "fail:no_dut_ack_to_replay_fin_in_time_wait_via_closing";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics14SM, tcp_basics_14)
