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

#include "tcp_closing_08_neg_sm.h"

namespace tc8::sce::cases {

using TcpClosing08NegSM = ::SCE::Generated::tcp_closing_08_neg::tcp_closing_08_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.8 TCP_CLOSING_08: a conformant DUT in FIN-WAIT-2 ACKs incoming
// data and stays in FW2 without emitting a FIN or RST (RFC 793 §3.5). kTcpSynthRstOnDisruptive
// makes the lwIP netif input hook synthesize the prohibited RST on the connection's 4-tuple
// when the FW2 data segment (PSH) arrives, and the case passes only when that synthesized RST
// is observed (the synth emits a RST, proving the dut_emitted_fin_or_rst_in_fw2 fail-final
// reachable). lwIP-only (kCapIngressFault). The ingress-synthesis sibling of the positive's
// FW2 absence guard — a case the egress field-fault cannot reach.
template <>
struct TestCaseTraits<cases::TcpClosing08NegSM>
    : TcpIngressFaultNegBase<cases::TcpClosing08NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_CLOSING_08_NEG";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_CLOSING_08: the lwIP kTcpSynthRstOnDisruptive ingress flavor "
        "makes the DUT emit a RST to data received in FIN-WAIT-2; a conformant DUT stays silent";

    static constexpr std::uint16_t kPayloadLen = 16U;

    // Mirrors the positive's FW2 prelude (half-close + tester auto-ACK of the FIN drives
    // FW1->FW2, NO AckDrop + in-window data inject acking the DUT FIN), with the fault armed
    // before the data so only the PSH segment elicits the synthesized RST. The data is injected
    // directly (not drained via receiveTcp): the synth fires at the netif hook on the inbound
    // PSH regardless of the DUT's receive.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        constexpr std::uint16_t kPortOffset = kTcpClosing08LocalOffset;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffset;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0 || !open.conn) return;
        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) return;

        // Half-close: shutdown(SHUT_WR) -> DUT FIN; the tester kernel auto-ACKs (no AckDrop)
        // so the DUT advances FW1 -> FW2.
        seamTcpControl(dut).shutdownTcpWr(open.conn->socket);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        // Per-phase arm after the DUT FIN + tester FIN-ACK (both excluded by the gate); the
        // eliciting data inject carries the arm settle so the raw-injected arm lands first.
        emitIngressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpSynthRstOnDisruptive);

        ::tc8::stimulus::TcpSegmentSpec data{};
        data.src_port = remote_port;
        data.dst_port = local_port;
        data.seq_num  = seq_range->snd_nxt;          // ISN_t + 1, in-window
        data.ack_num  = seq_range->rcv_nxt + 1U;     // ISN_d + 2, acks DUT FIN (benign dup)
        data.flags    = ::tc8::stimulus::kTcpFlagAck | ::tc8::stimulus::kTcpFlagPsh;
        data.payload.assign(kPayloadLen, 0x3CU);
        emitTcpFrame(cfg, iface, cfg.dut.mac, data, /*initial_wait=*/kFlavorArmSettle);

        std::this_thread::sleep_for(kSynthObserveHold);
        (void)tester_fd;
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpClosing08NegSM, tcp_closing_08_neg)
