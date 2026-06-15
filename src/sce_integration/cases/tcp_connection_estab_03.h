#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
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
    };

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view /*iface*/,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::array<Leg, 3> legs{
            Leg{static_cast<std::uint16_t>(kBasicsActiveLocalPort  + kTcpConnEstab03LocalOffset1),
                static_cast<std::uint16_t>(kBasicsActiveRemotePort + kTcpConnEstab03LocalOffset1)},
            Leg{static_cast<std::uint16_t>(kBasicsActiveLocalPort  + kTcpConnEstab03LocalOffset2),
                static_cast<std::uint16_t>(kBasicsActiveRemotePort + kTcpConnEstab03LocalOffset2)},
            Leg{static_cast<std::uint16_t>(kBasicsActiveLocalPort  + kTcpConnEstab03LocalOffset3),
                static_cast<std::uint16_t>(kBasicsActiveRemotePort + kTcpConnEstab03LocalOffset3)},
        };

        // Each leg's seam active open binds its own RAII tester listener that
        // absorbs the DUT's connect()-emitted SYN and completes the 3-way
        // handshake. Holding all three SeamActiveOpen results alive through the
        // stimulus keeps every listener up — drop one and the tester kernel
        // sends FIN-RST on that leg's connection.
        auto open1 = driveSeamActiveOpen(dut, cfg, legs[0].local_port, legs[0].remote_port);
        auto open2 = driveSeamActiveOpen(dut, cfg, legs[1].local_port, legs[1].remote_port);
        auto open3 = driveSeamActiveOpen(dut, cfg, legs[2].local_port, legs[2].remote_port);

        // Settle so all 3 third-leg ACKs land in pcap before close.
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        if (open1.conn) dut.tcpControl()->closeTcp(open1.conn->socket);
        if (open2.conn) dut.tcpControl()->closeTcp(open2.conn->socket);
        if (open3.conn) dut.tcpControl()->closeTcp(open3.conn->socket);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpConnectionEstab03SM, tcp_connection_estab_03)
