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

#include "tcp_header_02_neg_sm.h"

namespace tc8::sce::cases {

using TcpHeader02NegSM =
    ::SCE::Generated::tcp_header_02_neg::tcp_header_02_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.16 TCP_HEADER_02: kTcpFaultPureAckNumWrong flips the data-elicited
// ACK's ack_num so it no longer acknowledges the injected payload; a conformant DUT
// acks (snd_nxt + payload_len). The observed field is on the SECOND DUT pure ACK, so
// the fault is armed per-phase — the handshake is driven disarmed (its third-leg ACK
// escapes), then the flavor is armed before the data injection. lwIP-only
// (kCapEgressFault via TcpEgressFaultNegBase). Mirrors tcp_header_02's stimulus.
template <>
struct TestCaseTraits<cases::TcpHeader02NegSM>
    : TcpEgressFaultNegBase<cases::TcpHeader02NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_HEADER_02_NEG";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_HEADER_02: the lwIP kTcpFaultPureAckNumWrong egress "
        "flavor flips the data-elicited ACK's ack_num; a conformant DUT acks the payload";

    // Same 4 B in-window payload the positive injects — content is immaterial (the
    // fault corrupts ack_num regardless), only the length feeds expected_ack_num.
    static constexpr std::array<std::uint8_t, 4> kDataPayload = {
        0xC0U, 0xDEU, 0xCAU, 0xFEU};

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kTcpHeader02LocalOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kTcpHeader02LocalOffset;

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

        // Per-phase arm: the handshake third-leg ACK has already left (driveSeamActiveOpen
        // + acceptOne completed it), so arming now corrupts only the data-elicited ACK.
        emitEgressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpFaultPureAckNumWrong);

        ::tc8::stimulus::TcpSegmentSpec data{};
        data.src_port = remote_port;
        data.dst_port = local_port;
        data.seq_num  = injected_seq;
        data.ack_num  = seq_range->rcv_nxt;
        data.flags    = ::tc8::stimulus::kTcpFlagPsh
                      | ::tc8::stimulus::kTcpFlagAck;
        data.payload.assign(kDataPayload.begin(), kDataPayload.end());
        // Short pre-injection wait so the arm lands before the data elicits the ACK.
        emitTcpFrame(cfg, iface, cfg.dut.mac, data,
                     /*initial_wait=*/kFlavorArmSettle);
        ::close(tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpHeader02NegSM, tcp_header_02_neg)
