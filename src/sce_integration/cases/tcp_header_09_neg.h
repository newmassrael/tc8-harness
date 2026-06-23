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

#include "tcp_header_09_neg_sm.h"

namespace tc8::sce::cases {

using TcpHeader09NegSM = ::SCE::Generated::tcp_header_09_neg::tcp_header_09_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.16 TCP_HEADER_09: a conformant DUT silently drops a segment whose
// TCP Checksum is zero (an invalid checksum, RFC 793 §3.1). kTcpSynthAck makes the lwIP netif
// input hook synthesize the prohibited challenge ACK when the malformed segment arrives. Armed
// per-phase (after ESTABLISHED). lwIP-only (kCapIngressFault).
template <>
struct TestCaseTraits<cases::TcpHeader09NegSM>
    : TcpIngressFaultNegBase<cases::TcpHeader09NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_HEADER_09_NEG";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_HEADER_09: the lwIP kTcpSynthAck ingress flavor makes the DUT "
        "challenge-ACK a zero-checksum segment; a conformant DUT drops it silently";

    static constexpr std::array<std::uint8_t, 4> kDataPayload = {
        0xBAU, 0xADU, 0xF0U, 0x0DU};

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 37U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 37U;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            ::close(tester_fd);
            return;
        }

        // Per-phase arm: the handshake has completed, so the synthesis fires only on the
        // malformed segment injected next.
        emitIngressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpSynthAck);

        ::tc8::stimulus::TcpSegmentSpec data{};
        data.src_port                = remote_port;
        data.dst_port                = local_port;
        data.seq_num                 = seq_range->snd_nxt;
        data.ack_num                 = seq_range->rcv_nxt;
        data.flags                   = ::tc8::stimulus::kTcpFlagPsh
                                     | ::tc8::stimulus::kTcpFlagAck;
        data.payload.assign(kDataPayload.begin(), kDataPayload.end());
        data.force_zero_tcp_checksum = true;  // absolute 0x0000 checksum
        emitTcpFrame(cfg, iface, cfg.dut.mac, data,
                     /*initial_wait=*/std::chrono::milliseconds(0));
        (void)tester_fd;
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpHeader09NegSM, tcp_header_09_neg)
