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

#include "tcp_header_06_neg_sm.h"

namespace tc8::sce::cases {

using TcpHeader06NegSM =
    ::SCE::Generated::tcp_header_06_neg::tcp_header_06_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.16 TCP_HEADER_06: kTcpFaultPureAckNumWrong flips the data-elicited
// ACK's ack_num after the DUT ignores a non-zero Reserved field; a conformant DUT acks
// the payload. Per-phase arm (after the handshake) so only the data-ACK is corrupted.
// lwIP-only (kCapEgressFault). Mirrors tcp_header_06's stimulus on the +34 port quad.
template <>
struct TestCaseTraits<cases::TcpHeader06NegSM>
    : TcpEgressFaultNegBase<cases::TcpHeader06NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_HEADER_06_NEG";
    static constexpr std::string_view kSpecSection  = "4.8.6.16";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_HEADER_06: the lwIP kTcpFaultPureAckNumWrong egress "
        "flavor flips the Reserved=0xF data-ACK's ack_num; a conformant DUT acks the payload";

    static constexpr std::array<std::uint8_t, 4> kDataPayload = {
        0xFEU, 0xEDU, 0xFAU, 0xCEU};

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 34U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 34U;

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
        // 0x0F = all four RFC 793 §3.1 reserved bits, matching the positive.
        data.reserved_override = 0x0FU;
        emitTcpFrame(cfg, iface, cfg.dut.mac, data,
                     /*initial_wait=*/kEgressArmSettle);
        ::close(tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpHeader06NegSM, tcp_header_06_neg)
