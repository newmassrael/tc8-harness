#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_tcp_seam_passive_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_acknowledgement_03_neg_sm.h"

namespace tc8::sce::cases {

using TcpAcknowledgement03NegSM =
    ::SCE::Generated::tcp_acknowledgement_03_neg::tcp_acknowledgement_03_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.18 TCP_ACKNOWLEDGEMENT_03: kTcpFaultPureAckNumWrong flips
// the data-elicited ACK's ack_num so it no longer acknowledges the raw-injected payload;
// a conformant DUT acks it. The raw passive accept completes the handshake disarmed, then
// the flavor is armed before the data injection, so only the data-ACK is corrupted.
// lwIP-only (kCapEgressFault).
template <>
struct TestCaseTraits<cases::TcpAcknowledgement03NegSM>
    : TcpEgressFaultNegBase<cases::TcpAcknowledgement03NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_ACKNOWLEDGEMENT_03_NEG";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_ACKNOWLEDGEMENT_03: the lwIP kTcpFaultPureAckNumWrong "
        "egress flavor flips the data-elicited ACK's ack_num; a conformant DUT acks the payload";

    static constexpr std::array<std::uint8_t, 4> kDataPayload = {0xAC, 0x03, 0xDA, 0x7A};

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        auto open = driveSeamRawPassiveAccept(
            dut, cfg, iface,
            kTcpAck03ListenPort,
            std::vector<std::uint8_t>{},
            kTcpAck03TesterSrcPort);
        if (!open.conn) {
            return;
        }
        const std::uint32_t injected_seq = kTesterInitialSeq + 1U;
        const std::uint32_t payload_len  =
            static_cast<std::uint32_t>(kDataPayload.size());
        c.expected_ack_num = injected_seq + payload_len;

        // Per-phase arm: the handshake completed disarmed, so this corrupts only the
        // data-elicited ACK.
        emitEgressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpFaultPureAckNumWrong);

        ::tc8::stimulus::TcpSegmentSpec data{};
        data.src_port = kTcpAck03TesterSrcPort;
        data.dst_port = kTcpAck03ListenPort;
        data.seq_num  = injected_seq;
        data.ack_num  = open.dut_isn + 1U;
        data.flags    = ::tc8::stimulus::kTcpFlagPsh | ::tc8::stimulus::kTcpFlagAck;
        data.payload.assign(kDataPayload.begin(), kDataPayload.end());
        emitTcpFrame(cfg, iface, cfg.dut.mac, data,
                     /*initial_wait=*/kFlavorArmSettle);
        std::this_thread::sleep_for(kDelayedAckSettle);
        if (open.conn) {
            ::tc8::sce::seamTcpControl(dut).closeTcp(open.conn->socket);
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpAcknowledgement03NegSM, tcp_acknowledgement_03_neg)
