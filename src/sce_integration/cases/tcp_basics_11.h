#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_basics_11_sm.h"

namespace tc8::sce::cases {

using TcpBasics11SM = ::SCE::Generated::tcp_basics_11::tcp_basics_11;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics11SM>
    : TcpAnyBase<cases::TcpBasics11SM> {
    static constexpr std::string_view kCaseId       = "TCP_BASICS_11";
    static constexpr std::string_view kSpecSection  = "4.8.6.1";
    static constexpr std::string_view kDescription  =
        "TCP MUST move on to CLOSED state from TIME-WAIT state after "
        "a timeout of 2*MSL, where TIME-WAIT is reached through "
        "FINWAIT-2 (RFC 793 §3.2 p23 Terminology)";

    // Synchronous prelude (driveTcpToTimeWaitFw2) drives DUT into
    // TIME-WAIT. The post-2*MSL FIN-replay and DUT RST observation
    // is split into a state-entry observer chained with a wall-time
    // schedule:
    //   1. scheduleAfterStateEntry(Listening_replay_rst): fires the
    //      first tick after SCXML lands on the post-TIME-WAIT state.
    //   2. The observer enqueues schedule(kTimeWaitFullWait, …) so
    //      the actual raw-inject lands 72 s of wall-time later — the
    //      Linux DUT's TIME-WAIT timer (TCP_TIMEWAIT_LEN = 60 * HZ)
    //      has expired by then, and the (kBasicsActiveRemotePort,
    //      kBasicsActiveLocalPort) 4-tuple no longer matches a
    //      kernel socket, so `tcp_v4_send_reset` emits the
    //      closed-port RST per RFC 793 §3.4.
    //
    // Splitting the wait into "state-entry registration → wall-time
    // schedule" keeps the trait independent of the SCXML's deadline
    // value (78 s in this case) — the trait names the state
    // symbolically and the runner observes the transition.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const auto info = driveTcpToTimeWaitFw2(
            cfg, iface, cfg.dut.mac,
            /*open_req_id=*/1, /*close_req_id=*/2, /*socket_id=*/1,
            kBasicsActiveLocalPort  + kTcpBasics11LocalOffset,
            kBasicsActiveRemotePort + kTcpBasics11LocalOffset);
        if (!info.ok) return;

        std::string                 iface_copy(iface);
        ::tc8::TestConfig           cfg_copy   = cfg;
        std::array<std::uint8_t, 6> dut_mac    = cfg.dut.mac;
        const std::uint32_t         tester_seq = info.tester_seq_post_fin;
        const std::uint32_t         tester_ack = info.tester_ack_post_fin;
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_replay_rst),
            [&scheduler, iface_copy, cfg_copy, dut_mac,
             tester_seq, tester_ack]() {
                scheduler.schedule(
                    kTimeWaitFullWait,
                    [iface_copy, cfg_copy, dut_mac,
                     tester_seq, tester_ack]() {
                        ::tc8::stimulus::TcpSegmentSpec replay{};
                        replay.src_port = kBasicsActiveRemotePort + kTcpBasics11LocalOffset;
                        replay.dst_port = kBasicsActiveLocalPort  + kTcpBasics11LocalOffset;
                        replay.seq_num  = tester_seq;
                        replay.ack_num  = tester_ack;
                        replay.flags    = ::tc8::stimulus::kTcpFlagFin
                                        | ::tc8::stimulus::kTcpFlagAck;
                        emitTcpFrame(cfg_copy, iface_copy, dut_mac, replay,
                                     /*initial_wait=*/std::chrono::milliseconds(0));
                    });
            });
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_no_handshake_ack:      return "fail:no_dut_handshake_ack";
            case State::Fail_no_close_fin:          return "fail:no_dut_close_fin";
            case State::Fail_no_tester_fin_ack:     return "fail:no_dut_ack_to_tester_fin";
            case State::Fail_no_replay_rst:         return "fail:no_dut_rst_after_2msl_post_time_wait";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics11SM, tcp_basics_11)
