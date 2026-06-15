#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_passive_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"

#include "tcp_sequence_04_sm.h"

namespace tc8::sce::cases {

using TcpSequence04SM =
    ::SCE::Generated::tcp_sequence_04::tcp_sequence_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpSequence04SM>
    : TcpAnyBase<cases::TcpSequence04SM> {
    static constexpr std::string_view kCaseId       = "TCP_SEQUENCE_04";
    static constexpr std::string_view kSpecSection  = "4.8.6.17";
    static constexpr std::string_view kDescription  =
        "DUT accepts SYN with Sequence Number = SeqMaxVal (0xFFFFFFFF) "
        "and emits SYN,ACK with ack_num wrapping to 0 (RFC 793 §3.1 "
        "modulo-32 arithmetic).";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // Tester SYN ISN = SeqMaxVal (0xFFFFFFFF); the DUT SYN+ACK ack_num
        // must wrap modulo-32 to 0, which the SCXML asserts during the
        // handshake. rawPassiveThreeWayHandshake's third-leg ACK seq is
        // tester_isn + 1 == 0, exercising the same wraparound on the tester side.
        auto open = driveSeamRawPassiveAccept(
            dut, cfg, iface,
            kTcpSequence04ListenPort,
            std::vector<std::uint8_t>{},
            kTcpSequence04TesterSrcPort,
            /*tester_isn=*/0xFFFFFFFFU);

        if (open.conn) {
            ::tc8::sce::seamTcpControl(dut).closeTcp(open.conn->socket);
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpSequence04SM, tcp_sequence_04)
