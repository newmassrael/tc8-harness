#pragma once

#include <array>
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
#include "stimulus/tcp_segment_builder.h"

#include "tcp_acknowledgement_03_sm.h"

namespace tc8::sce::cases {

using TcpAcknowledgement03SM =
    ::SCE::Generated::tcp_acknowledgement_03::tcp_acknowledgement_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpAcknowledgement03SM>
    : TcpAnyBase<cases::TcpAcknowledgement03SM> {
    static constexpr std::string_view kCaseId       = "TCP_ACKNOWLEDGEMENT_03";
    static constexpr std::string_view kSpecSection  = "4.8.6.18";
    static constexpr std::string_view kDescription  =
        "DUT replies to a tester-injected data segment with a pure ACK "
        "whose ack_num covers the payload (RFC 793 p74).";

    static constexpr std::array<std::uint8_t, 4> kDataPayload = {
        0xC0U, 0xDEU, 0xCAU, 0xFEU};

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const auto open = driveSeamRawPassiveAccept(
            dut, cfg, iface,
            kTcpAck03ListenPort,
            std::vector<std::uint8_t>{},
            kTcpAck03TesterSrcPort);
        if (!open.conn) return;  // no accepted connection ⇒ no DUT to ack/close

        const std::uint32_t injected_seq = kTesterInitialSeq + 1U;
        const std::uint32_t payload_len  =
            static_cast<std::uint32_t>(kDataPayload.size());
        c.expected_ack_num = injected_seq + payload_len;

        ::tc8::stimulus::TcpSegmentSpec data{};
        data.src_port = kTcpAck03TesterSrcPort;
        data.dst_port = kTcpAck03ListenPort;
        data.seq_num  = injected_seq;
        data.ack_num  = open.dut_isn + 1U;
        data.flags    = ::tc8::stimulus::kTcpFlagPsh
                      | ::tc8::stimulus::kTcpFlagAck;
        data.payload.assign(kDataPayload.begin(), kDataPayload.end());
        emitTcpFrame(cfg, iface, cfg.dut.mac, data,
                     /*initial_wait=*/std::chrono::milliseconds(0));

        // The spec procedure has no close step; the follow-up
        // OpCloseTcpSocket is harness teardown. A delayed-ACK DUT (lwIP)
        // holds the data ACK up to the RFC 1122 §4.2.3.2 ceiling, and a
        // close arriving over the still-unread RX byte converts the
        // pending ACK into an RST — losing the very ACK the case
        // observes. Settle past the ceiling (kDelayedAckSettle) so the
        // pure data ACK is on the wire before teardown; a quickack DUT
        // (Linux) has already ACKed and is unaffected by the extra wait.
        std::this_thread::sleep_for(kDelayedAckSettle);
        if (open.conn) {
            ::tc8::sce::seamTcpControl(dut).closeTcp(open.conn->socket);
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpAcknowledgement03SM, tcp_acknowledgement_03)
