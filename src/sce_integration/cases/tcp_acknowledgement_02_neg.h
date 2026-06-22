#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_acknowledgement_02_neg_sm.h"

namespace tc8::sce::cases {

using TcpAcknowledgement02NegSM =
    ::SCE::Generated::tcp_acknowledgement_02_neg::tcp_acknowledgement_02_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.18 TCP_ACKNOWLEDGEMENT_02: kTcpFaultPureAckNumWrong flips
// the data-elicited ACK's ack_num so it no longer acknowledges the piggybacked payload;
// a conformant DUT acks it. The observed ACK is the second DUT pure ACK, so the fault is
// armed per-phase — the active OPEN + DUT data send is driven disarmed, then the flavor
// is armed before the tester data injection. lwIP-only (kCapEgressFault).
template <>
struct TestCaseTraits<cases::TcpAcknowledgement02NegSM>
    : TcpEgressFaultNegBase<cases::TcpAcknowledgement02NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_ACKNOWLEDGEMENT_02_NEG";
    static constexpr std::string_view kSpecSection  = "4.8.6.18";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_ACKNOWLEDGEMENT_02: the lwIP kTcpFaultPureAckNumWrong "
        "egress flavor flips the data-elicited ACK's ack_num; a conformant DUT acks the payload";

    // Content immaterial (the fault corrupts ack_num regardless); only the tester
    // payload's length feeds expected_ack_num. Same 4 B shapes as the positive.
    static constexpr std::array<std::uint8_t, 4> kDutPayload    = {0xD0, 0x71, 0x55, 0x01};
    static constexpr std::array<std::uint8_t, 4> kTesterPayload = {0x7E, 0x57, 0x2A, 0xCC};

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kTcpAck02LocalOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kTcpAck02LocalOffset;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0 || !open.conn) {
            return;
        }
        seamSendTcp(dut, open.conn->socket, kDutPayload);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            ::close(tester_fd);
            return;
        }
        const std::uint32_t injected_seq  = seq_range->snd_nxt;
        const std::uint32_t tester_paylen =
            static_cast<std::uint32_t>(kTesterPayload.size());
        c.expected_ack_num = injected_seq + tester_paylen;

        // Per-phase arm: the handshake ACK and the DUT data send have left, so this
        // corrupts only the data-elicited ACK.
        emitEgressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpFaultPureAckNumWrong);

        ::tc8::stimulus::TcpSegmentSpec data{};
        data.src_port = remote_port;
        data.dst_port = local_port;
        data.seq_num  = injected_seq;
        data.ack_num  = seq_range->rcv_nxt;
        data.flags    = ::tc8::stimulus::kTcpFlagPsh | ::tc8::stimulus::kTcpFlagAck;
        data.payload.assign(kTesterPayload.begin(), kTesterPayload.end());
        emitTcpFrame(cfg, iface, cfg.dut.mac, data,
                     /*initial_wait=*/kEgressArmSettle);
        ::close(tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpAcknowledgement02NegSM, tcp_acknowledgement_02_neg)
