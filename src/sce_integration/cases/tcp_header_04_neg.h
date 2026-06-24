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

#include "tcp_header_04_neg_sm.h"

namespace tc8::sce::cases {

using TcpHeader04NegSM = ::SCE::Generated::tcp_header_04_neg::tcp_header_04_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.16 TCP_HEADER_04: a conformant DUT demultiplexes an inbound segment by
// the full 4-tuple (RFC 793 §3.1 / §3.9), so it drops an in-window data segment whose source port
// differs from the established peer's and emits no ACK on the EST 4-tuple. kTcpSynthAckSrcPortBlind
// makes the lwIP netif input hook walk tcp_active_pcbs and synthesize the prohibited pure ACK on the
// EST 4-tuple (recovered from the connection's real remote port — the wrong-source-port trigger does
// not carry it); the case passes only when that synthesized ACK is observed. lwIP-only
// (kCapIngressFault). A §4.8 must-not-respond case the ingress-synthesis seam reaches but the egress
// field-fault cannot — the conformant DUT emits no segment to corrupt.
template <>
struct TestCaseTraits<cases::TcpHeader04NegSM>
    : TcpIngressFaultNegBase<cases::TcpHeader04NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_HEADER_04_NEG";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_HEADER_04: the lwIP kTcpSynthAckSrcPortBlind ingress flavor makes "
        "the DUT ACK an in-window data segment from the wrong source port (source-port-blind demux); "
        "a conformant DUT drops it and stays silent on the EST 4-tuple";

    static constexpr std::array<std::uint8_t, 4> kDataPayload = {
        0xC0U, 0xFFU, 0xEEU, 0x00U};

    // Mirrors the positive's active-OPEN seam: drive the DUT to ESTABLISHED on the EST quad, then
    // raw-inject the spec-asserted PSH+ACK whose SOURCE port is the deliberately-wrong PORT2. The
    // fault is armed after ESTABLISHED (the handshake's third-leg ACK has confirmed the connection)
    // and before the wrong-port inject, so only that segment elicits the synthesized ACK. The tester
    // fd is left open across the observe window — closing it would send a FIN the DUT ACKs on the EST
    // 4-tuple, which the watch would misread as the synthesized ACK (the positive keeps it open too).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kTcpHeader04LocalOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kTcpHeader04LocalOffset;
        // PORT2 — the deliberately-wrong tester SOURCE port (kTcpHeader04WrongRemotePort,
        // SSOT in tcp_pilot_common.h), shared with the positive.
        const std::uint16_t wrong_remote_port = kTcpHeader04WrongRemotePort;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            ::close(tester_fd);
            return;
        }

        emitIngressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpSynthAckSrcPortBlind);

        ::tc8::stimulus::TcpSegmentSpec data{};
        data.src_port = wrong_remote_port;
        data.dst_port = local_port;
        data.seq_num  = seq_range->snd_nxt;
        data.ack_num  = seq_range->rcv_nxt;
        data.flags    = ::tc8::stimulus::kTcpFlagPsh
                      | ::tc8::stimulus::kTcpFlagAck;
        data.payload.assign(kDataPayload.begin(), kDataPayload.end());
        emitTcpFrame(cfg, iface, cfg.dut.mac, data, /*initial_wait=*/kFlavorArmSettle);
        std::this_thread::sleep_for(kSynthObserveHold);
        (void)tester_fd;
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpHeader04NegSM, tcp_header_04_neg)
