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

#include "tcp_sequence_03_sm.h"

namespace tc8::sce::cases {

using TcpSequence03SM =
    ::SCE::Generated::tcp_sequence_03::tcp_sequence_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpSequence03SM>
    : TcpAnyBase<cases::TcpSequence03SM> {
    static constexpr std::string_view kCaseId       = "TCP_SEQUENCE_03";
    static constexpr std::string_view kDescription  =
        "DUT accepts SYN with Sequence Number = 0 and emits SYN,ACK "
        "with ack_num == 1 (RFC 793 §3.1).";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // Tester SYN ISN = 0 (the zero-sequence case); the DUT
        // SYN+ACK ack_num is asserted == 1 by the SCXML during the handshake.
        auto open = driveSeamRawPassiveAccept(
            dut, cfg, iface,
            kTcpSequence03ListenPort,
            std::vector<std::uint8_t>{},
            kTcpSequence03TesterSrcPort,
            /*tester_isn=*/0U);

        if (open.conn) {
            ::tc8::sce::seamTcpControl(dut).closeTcp(open.conn->socket);
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpSequence03SM, tcp_sequence_03)
