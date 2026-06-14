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

#include "tcp_acknowledgement_04_sm.h"

namespace tc8::sce::cases {

using TcpAcknowledgement04SM =
    ::SCE::Generated::tcp_acknowledgement_04::tcp_acknowledgement_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpAcknowledgement04SM>
    : TcpAnyBase<cases::TcpAcknowledgement04SM> {
    static constexpr std::string_view kCaseId       = "TCP_ACKNOWLEDGEMENT_04";
    static constexpr std::string_view kSpecSection  = "4.8.6.18";
    static constexpr std::string_view kDescription  =
        "DUT receives a pure ACK (Length=0, no piggybacking) and MUST "
        "NOT emit RST; the connection ends cleanly when requested "
        "(RFC 793 §3.9 Event Processing).";

    static constexpr std::array<std::uint8_t, 4> kDutPayload = {
        0xACU, 0xDCU, 0x04U, 0x00U};

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view /*iface*/,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort  + kTcpAck04LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpAck04LocalOffset;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0 || !open.conn) return;

        seamSendTcp(dut, open.conn->socket, kDutPayload);

        std::this_thread::sleep_for(std::chrono::seconds(3) +
                                     std::chrono::milliseconds(200));

        dut.tcpControl()->closeTcp(open.conn->socket);
        (void)tester_fd;
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                              return "pass";
            case State::Fail_no_handshake_ack:             return "fail:no_dut_handshake_ack";
            case State::Fail_dut_rst_after_pure_ack:       return "fail:dut_emitted_rst_after_pure_ack";
            case State::Fail_no_dut_fin:                   return "fail:no_dut_fin_after_close_request";
            default:                                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpAcknowledgement04SM, tcp_acknowledgement_04)
