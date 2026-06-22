#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_closing_07_neg_sm.h"

namespace tc8::sce::cases {

using TcpClosing07NegSM = ::SCE::Generated::tcp_closing_07_neg::tcp_closing_07_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.8 TCP_CLOSING_07: a conformant DUT in FIN-WAIT-1 ACKs incoming
// data and stays in FW1 without emitting a RST (RFC 793 §3.5). kTcpSynthRstOnDisruptive makes
// the lwIP netif input hook synthesize the prohibited RST on the connection's 4-tuple when the
// FW1 data segment (PSH) arrives, and the case passes only when that synthesized RST is
// observed. lwIP-only (kCapIngressFault). A §4.8 must-not-respond case the ingress-synthesis
// seam reaches but the egress field-fault cannot — the conformant DUT emits no RST to corrupt.
template <>
struct TestCaseTraits<cases::TcpClosing07NegSM>
    : TcpIngressFaultNegBase<cases::TcpClosing07NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_CLOSING_07_NEG";
    static constexpr std::string_view kSpecSection  = "4.8.6.8";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_CLOSING_07: the lwIP kTcpSynthRstOnDisruptive ingress flavor "
        "makes the DUT emit a RST to data received in FIN-WAIT-1; a conformant DUT stays silent";

    static constexpr std::uint16_t kPayloadLen = 16U;

    // Mirrors the positive's FW1 prelude (TesterAutoAckDrop holds FW1 by suppressing the
    // tester's auto-ACK of the DUT FIN + half-close + in-window data inject), with the fault
    // armed before the data so only the PSH segment elicits the synthesized RST. A stack
    // AckDrop suffices (no 120 s keepalive): the synthesized RST is observed immediately, well
    // inside the post-inject hold. The data is injected directly (not drained via receiveTcp):
    // the synth fires at the netif hook on the inbound PSH regardless of the DUT's receive.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        constexpr std::uint16_t kPortOffset = 73U;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffset;

        TesterAutoAckDrop ack_drop(cfg);
        (void)ack_drop;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0 || !open.conn) return;
        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) return;

        // Half-close: shutdown(SHUT_WR) -> DUT FIN, EST->FW1; AckDrop holds FW1.
        seamTcpControl(dut).shutdownTcpWr(open.conn->socket);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        // Per-phase arm after the DUT FIN (egress, excluded by the gate); the eliciting data
        // inject carries the arm settle so the raw-injected arm lands first.
        emitIngressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpSynthRstOnDisruptive);

        ::tc8::stimulus::TcpSegmentSpec data{};
        data.src_port = remote_port;
        data.dst_port = local_port;
        data.seq_num  = seq_range->snd_nxt;          // ISN_t + 1, in-window
        data.ack_num  = seq_range->rcv_nxt;          // ISN_d + 1, doesn't ack DUT FIN
        data.flags    = ::tc8::stimulus::kTcpFlagAck | ::tc8::stimulus::kTcpFlagPsh;
        data.payload.assign(kPayloadLen, 0x69U);
        emitTcpFrame(cfg, iface, cfg.dut.mac, data, /*initial_wait=*/kFlavorArmSettle);

        // Hold FW1 (AckDrop alive) while the synthesized RST is observed.
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        (void)tester_fd;
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpClosing07NegSM, tcp_closing_07_neg)
