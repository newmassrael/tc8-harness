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

#include "tcp_header_05_neg_sm.h"

namespace tc8::sce::cases {

using TcpHeader05NegSM =
    ::SCE::Generated::tcp_header_05_neg::tcp_header_05_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.16 TCP_HEADER_05: kTcpFaultPureAckNumWrong flips the data-elicited
// ACK's ack_num after the DUT accepts Reserved=0 data; a conformant DUT acks the
// payload. Per-phase arm (after the handshake) so only the data-ACK is corrupted.
// lwIP-only (kCapEgressFault). Mirrors tcp_header_05's stimulus on the +33 port quad.
template <>
struct TestCaseTraits<cases::TcpHeader05NegSM>
    : TcpEgressFaultNegBase<cases::TcpHeader05NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_HEADER_05_NEG";
    static constexpr std::string_view kSpecSection  = "4.8.6.16";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_HEADER_05: the lwIP kTcpFaultPureAckNumWrong egress "
        "flavor flips the Reserved=0 data-ACK's ack_num; a conformant DUT acks the payload";

    static constexpr std::array<std::uint8_t, 4> kDataPayload = {
        0xC0U, 0xDEU, 0xBEU, 0xEFU};

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 33U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 33U;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) {
            return;
        }
        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            ::close(tester_fd);
            return;
        }
        const std::uint32_t injected_seq = seq_range->snd_nxt;
        const std::uint32_t payload_len  =
            static_cast<std::uint32_t>(kDataPayload.size());
        c.expected_ack_num = injected_seq + payload_len;

        // Per-phase arm: the handshake third-leg ACK has already left, so this corrupts
        // only the data-elicited ACK.
        emitEgressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpFaultPureAckNumWrong);

        ::tc8::stimulus::TcpSegmentSpec data{};
        data.src_port          = remote_port;
        data.dst_port          = local_port;
        data.seq_num           = injected_seq;
        data.ack_num           = seq_range->rcv_nxt;
        data.flags             = ::tc8::stimulus::kTcpFlagPsh
                               | ::tc8::stimulus::kTcpFlagAck;
        data.payload.assign(kDataPayload.begin(), kDataPayload.end());
        data.reserved_override = 0x00U;
        emitTcpFrame(cfg, iface, cfg.dut.mac, data,
                     /*initial_wait=*/kFlavorArmSettle);
        ::close(tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpHeader05NegSM, tcp_header_05_neg)
