#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_connection_estab_07_sm.h"

namespace tc8::sce::cases {

using TcpConnectionEstab07SM =
    ::SCE::Generated::tcp_connection_estab_07::tcp_connection_estab_07;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpConnectionEstab07SM>
    : TcpAnyBase<cases::TcpConnectionEstab07SM> {
    static constexpr std::string_view kCaseId       = "TCP_CONNECTION_ESTAB_07";
    static constexpr std::string_view kSpecSection  = "4.8.6.15";
    static constexpr std::string_view kDescription  =
        "DUT acks tester FIN and on user Close emits its own FIN to "
        "reach CLOSED (RFC 793 §3.5 Closing a Connection).";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);
        sendOpenTcpSocketPassiveRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/1, kTcpConnEstab07ListenPort);
        std::this_thread::sleep_for(kTcpUtRpcWait);

        int client_fd = -1;
        connectToDutTcp(cfg, kTcpConnEstab07ListenPort,
                         TcpPostClose::kShutdownWr, &client_fd);
        // Phase 1: tester FIN → DUT auto-ACK observed by SCXML.
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // Phase 2: UT close → tc8-dut close() → DUT FIN observed.
        sendCloseTcpSocketRequest(cfg, iface, cfg.arp.dut_real_mac,
                                   /*req_id=*/2, /*socket_id=*/1);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        if (client_fd >= 0) ::close(client_fd);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:               return "pass";
            case State::Fail_timeout_ack:   return "fail:no_dut_ack_to_tester_fin";
            case State::Fail_timeout_fin:   return "fail:no_dut_fin_after_close";
            default:                        return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpConnectionEstab07SM, tcp_connection_estab_07)
