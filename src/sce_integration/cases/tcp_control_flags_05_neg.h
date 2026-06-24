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

#include "tcp_control_flags_05_neg_sm.h"

namespace tc8::sce::cases {

using TcpControlFlags05NegSM =
    ::SCE::Generated::tcp_control_flags_05_neg::tcp_control_flags_05_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.19 TCP_CONTROL_FLAGS_05: kTcpFaultPureAckNumWrong flips
// the URG-elicited ACK's ack_num so it no longer acknowledges the urgent payload; a
// conformant DUT acks it. The observed ACK is the second DUT pure ACK, so the fault is
// armed per-phase — the active OPEN is driven disarmed (handshake third-leg ACK escapes
// conformant), then the flavor is armed before the URG injection. Same recipe as
// TCP_ACKNOWLEDGEMENT_02_NEG (the twin invariant). lwIP-only (kCapEgressFault).
template <>
struct TestCaseTraits<cases::TcpControlFlags05NegSM>
    : TcpEgressFaultNegBase<cases::TcpControlFlags05NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_CONTROL_FLAGS_05_NEG";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_CONTROL_FLAGS_05: the lwIP kTcpFaultPureAckNumWrong "
        "egress flavor flips the URG-elicited ACK's ack_num; a conformant DUT acks the payload";

    // Same 4 B urgent payload as the positive; content immaterial (the fault corrupts
    // ack_num regardless), only its length feeds expected_ack_num.
    static constexpr std::array<std::uint8_t, 4> kUrgPayload = {0xC0U, 0xDEU, 0xCAU, 0xFEU};

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort  + kTcpControlFlags05LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpControlFlags05LocalOffset;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            ::close(tester_fd);
            return;
        }
        const std::uint32_t injected_seq = seq_range->snd_nxt;
        const std::uint32_t payload_len  =
            static_cast<std::uint32_t>(kUrgPayload.size());
        c.expected_ack_num = injected_seq + payload_len;

        // Per-phase arm: the handshake third-leg ACK has left, so this corrupts only
        // the URG-elicited pure ACK (the connection stays up).
        emitEgressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpFaultPureAckNumWrong);

        ::tc8::stimulus::TcpSegmentSpec urg_seg{};
        urg_seg.src_port       = remote_port;
        urg_seg.dst_port       = local_port;
        urg_seg.seq_num        = injected_seq;
        urg_seg.ack_num        = seq_range->rcv_nxt;
        urg_seg.flags          = ::tc8::stimulus::kTcpFlagUrg
                               | ::tc8::stimulus::kTcpFlagPsh
                               | ::tc8::stimulus::kTcpFlagAck;
        urg_seg.urgent_pointer =
            static_cast<std::uint16_t>(kUrgPayload.size());
        urg_seg.payload.assign(kUrgPayload.begin(), kUrgPayload.end());
        emitTcpFrame(cfg, iface, cfg.dut.mac, urg_seg,
                     /*initial_wait=*/kFlavorArmSettle);
        ::close(tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpControlFlags05NegSM, tcp_control_flags_05_neg)
