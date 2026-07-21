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

#include "tcp_header_07_neg_sm.h"

namespace tc8::sce::cases {

using TcpHeader07NegSM = ::SCE::Generated::tcp_header_07_neg::tcp_header_07_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.16 TCP_HEADER_07: a conformant DUT silently drops a segment whose
// Data Offset < 5 (RFC 793 §3.1). kTcpSynthAck makes the lwIP netif input hook synthesize the
// prohibited challenge ACK on the connection 4-tuple when the malformed segment arrives. Armed
// per-phase (after ESTABLISHED) so the handshake SYN,ACK is not mistaken for the trigger.
// lwIP-only (kCapIngressFault). One of the §4.8 must-not-respond cases the ingress-synthesis
// seam reaches but the egress field-fault cannot (the conformant DUT emits nothing).
template <>
struct TestCaseTraits<cases::TcpHeader07NegSM>
    : TcpIngressFaultNegBase<cases::TcpHeader07NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_HEADER_07_NEG";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_HEADER_07: the lwIP kTcpSynthAck ingress flavor makes the DUT "
        "challenge-ACK a Data-Offset<5 segment; a conformant DUT drops it silently";

    static constexpr std::array<std::uint8_t, 4> kDataPayload = {
        0xBAU, 0xADU, 0xF0U, 0x0DU};

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kTcpHeader07LocalOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kTcpHeader07LocalOffset;

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
        data.src_port             = remote_port;
        data.dst_port             = local_port;
        data.seq_num              = seq_range->snd_nxt;
        data.ack_num              = seq_range->rcv_nxt;
        data.flags                = ::tc8::stimulus::kTcpFlagPsh
                                  | ::tc8::stimulus::kTcpFlagAck;
        data.payload.assign(kDataPayload.begin(), kDataPayload.end());
        data.data_offset_override = 0x04U;  // < RFC 793 minimum of 5
        emitTcpFrame(cfg, iface, cfg.dut.mac, data,
                     /*initial_wait=*/std::chrono::milliseconds(0));
        (void)tester_fd;
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpHeader07NegSM, tcp_header_07_neg)
