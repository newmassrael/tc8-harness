#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_connection_estab_03_sm.h"

namespace tc8::sce::cases {

using TcpConnectionEstab03SM =
    ::SCE::Generated::tcp_connection_estab_03::tcp_connection_estab_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpConnectionEstab03SM>
    : TcpAnyBase<cases::TcpConnectionEstab03SM> {
    static constexpr std::string_view kCaseId       = "TCP_CONNECTION_ESTAB_03";
    static constexpr std::string_view kSpecSection  = "4.8.6.15";
    static constexpr std::string_view kDescription  =
        "DUT opens 3 active sockets and completes the 3-way "
        "handshake on each (RFC 793 §3.4).";

    struct Leg {
        std::uint16_t local_port;
        std::uint16_t remote_port;
        std::uint8_t  socket_id;
    };

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::array<Leg, 3> legs{
            Leg{static_cast<std::uint16_t>(kBasicsActiveLocalPort  + kTcpConnEstab03LocalOffset1),
                static_cast<std::uint16_t>(kBasicsActiveRemotePort + kTcpConnEstab03LocalOffset1), 1U},
            Leg{static_cast<std::uint16_t>(kBasicsActiveLocalPort  + kTcpConnEstab03LocalOffset2),
                static_cast<std::uint16_t>(kBasicsActiveRemotePort + kTcpConnEstab03LocalOffset2), 2U},
            Leg{static_cast<std::uint16_t>(kBasicsActiveLocalPort  + kTcpConnEstab03LocalOffset3),
                static_cast<std::uint16_t>(kBasicsActiveRemotePort + kTcpConnEstab03LocalOffset3), 3U},
        };

        // Each leg has its own RAII tester listener that absorbs the
        // DUT's connect()-emitted SYN. Holding the listeners alive
        // through the entire stimulus prevents tester-kernel auto-RST
        // on the connected sockets — drop a listener and the kernel
        // sends FIN-RST on the leg's queued connection.
        TesterTcpListener l1(legs[0].remote_port);
        TesterTcpListener l2(legs[1].remote_port);
        TesterTcpListener l3(legs[2].remote_port);

        for (std::uint8_t i = 0; i < legs.size(); ++i) {
            sendOpenTcpSocketActiveRequest(
                cfg, iface, cfg.dut.mac,
                /*req_id=*/static_cast<std::uint8_t>(i + 1U),
                legs[i].local_port,
                cfg.ipv4.tester_ip, legs[i].remote_port);
            std::this_thread::sleep_for(kTcpUtRpcWait);
        }
        std::this_thread::sleep_for(kTcpActiveHandshakeGrace);

        // Settle so all 3 third-leg ACKs land in pcap before close.
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        for (std::uint8_t i = 0; i < legs.size(); ++i) {
            sendCloseTcpSocketRequest(
                cfg, iface, cfg.dut.mac,
                /*req_id=*/static_cast<std::uint8_t>(i + 4U),
                legs[i].socket_id);
        }
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                return "pass";
            case State::Fail_timeout_leg1:   return "fail:no_dut_handshake_ack_for_leg1";
            case State::Fail_timeout_leg2:   return "fail:no_dut_handshake_ack_for_leg2";
            case State::Fail_timeout_leg3:   return "fail:no_dut_handshake_ack_for_leg3";
            default:                         return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpConnectionEstab03SM, tcp_connection_estab_03)
