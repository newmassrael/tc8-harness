#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_closing_06_sm.h"

namespace tc8::sce::cases {

using TcpClosing06SM = ::SCE::Generated::tcp_closing_06::tcp_closing_06;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpClosing06SM>
    : TcpAnyBase<cases::TcpClosing06SM> {
    static constexpr std::string_view kCaseId       = "TCP_CLOSING_06";
    static constexpr std::string_view kSpecSection  = "4.8.6.8";
    static constexpr std::string_view kDescription  =
        "TCP in ESTABLISHED state MUST send a FIN segment when the "
        "local user issues a CLOSE call (RFC 793 §3.5 p38 Closing a "
        "Connection)";

    // Single iteration. Active-OPEN handshake on (kBasicsActiveLocalPort
    // + 70, kBasicsActiveRemotePort + 70) drives DUT to ESTABLISHED;
    // accept the tester-side fd, then UT OpCloseTcpSocket triggers DUT's
    // tcp_close which enqueues a FIN+ACK on the connection. The tester
    // fd is left open through harness teardown — the spec assertion is
    // "DUT sent a FIN" and any kernel auto-ACK to that FIN does not
    // affect the pass guard. Port quad +70 reserves the §4.8.6.8
    // active-OPEN block.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        constexpr std::uint16_t kPortOffset = 70U;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffset;

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.dut.mac,
            /*open_req_id=*/1, local_port, remote_port);
        const int tester_fd = listener.acceptOne();
        if (tester_fd < 0) return;

        sendCloseTcpSocketRequest(
            cfg, iface, cfg.dut.mac,
            /*close_req_id=*/2, /*socket_id=*/1);
        (void)tester_fd;
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_no_handshake_ack:      return "fail:no_dut_handshake_ack";
            case State::Fail_no_dut_fin:            return "fail:no_dut_close_fin";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpClosing06SM, tcp_closing_06)
