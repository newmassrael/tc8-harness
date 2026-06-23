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

#include "tcp_checksum_02_neg_sm.h"

namespace tc8::sce::cases {

using TcpChecksum02NegSM = ::SCE::Generated::tcp_checksum_02_neg::tcp_checksum_02_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.2 TCP_CHECKSUM_02: a conformant DUT silently drops a data segment
// whose TCP checksum is wrong and does NOT acknowledge it (RFC 1122 §4.2.2.7). kTcpSynthAck makes
// the lwIP netif input hook synthesize the prohibited forward ACK on the connection 4-tuple when
// the corrupt-checksum data segment arrives — the hook reads the 4-tuple at fixed offsets, so the
// bad checksum is irrelevant to firing. Armed per-phase (after ESTABLISHED) so the handshake
// SYN,ACK is not mistaken for the trigger. lwIP-only (kCapIngressFault). One of the §4.8
// must-not-respond cases the ingress-synthesis seam reaches but the egress field-fault cannot
// (the conformant DUT emits nothing).
template <>
struct TestCaseTraits<cases::TcpChecksum02NegSM>
    : TcpIngressFaultNegBase<cases::TcpChecksum02NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_CHECKSUM_02_NEG";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_CHECKSUM_02: the lwIP kTcpSynthAck ingress flavor makes the DUT "
        "ACK a corrupt-checksum data segment; a conformant DUT drops it silently";

    static constexpr std::array<std::uint8_t, 4> kDataPayload = {
        0xDEU, 0xADU, 0xBEU, 0xEFU};

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 40U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 40U;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            ::close(tester_fd);
            return;
        }

        // Per-phase arm: the handshake has completed, so the synthesis fires only on the
        // corrupt-checksum segment injected next.
        emitIngressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpSynthAck);

        ::tc8::stimulus::TcpSegmentSpec data{};
        data.src_port             = remote_port;
        data.dst_port             = local_port;
        data.seq_num              = seq_range->snd_nxt;
        data.ack_num              = seq_range->rcv_nxt;
        data.flags                = ::tc8::stimulus::kTcpFlagPsh
                                  | ::tc8::stimulus::kTcpFlagAck;
        data.payload.assign(kDataPayload.begin(), kDataPayload.end());
        data.corrupt_tcp_checksum = true;
        emitTcpFrame(cfg, iface, cfg.dut.mac, data,
                     /*initial_wait=*/std::chrono::milliseconds(0));
        (void)tester_fd;
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpChecksum02NegSM, tcp_checksum_02_neg)
