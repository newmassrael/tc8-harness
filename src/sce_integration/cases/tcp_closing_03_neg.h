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

#include "tcp_closing_03_neg_sm.h"

namespace tc8::sce::cases {

using TcpClosing03NegSM = ::SCE::Generated::tcp_closing_03_neg::tcp_closing_03_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.8 TCP_CLOSING_03: a conformant DUT in ESTABLISHED that receives an
// in-window RST carrying data transitions to CLOSED silently, emitting no reply (RFC 1122
// §4.2.2.12 / RFC 793 §3.4). kTcpSynthRstOnDisruptive makes the lwIP netif input hook synthesize
// the prohibited RST on the connection's 4-tuple when the RST+ACK+data segment arrives (the RST
// flag trips the disruptive-union gate), and the case passes only when that synthesized RST is
// observed. lwIP-only (kCapIngressFault). A §4.8 must-not-respond case the ingress-synthesis
// seam reaches but the egress field-fault cannot — the conformant DUT emits no segment to corrupt.
template <>
struct TestCaseTraits<cases::TcpClosing03NegSM>
    : TcpIngressFaultNegBase<cases::TcpClosing03NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_CLOSING_03_NEG";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_CLOSING_03: the lwIP kTcpSynthRstOnDisruptive ingress flavor "
        "makes the DUT emit a RST to an in-window RST-with-data in ESTABLISHED; a conformant DUT "
        "closes silently";

    // 16-byte payload matching the positive's RST-with-data wire shape (0xA5 pattern); the synth
    // fires on the RST flag regardless of payload, but the data keeps the trigger a faithful
    // mirror of the positive's "RST containing some data".
    static constexpr std::size_t kRstPayloadLen = 16U;

    // Mirrors the positive's EST seam (driveSeamActiveOpen + acceptOne + queryTcpSeqRange) with
    // the fault armed after the handshake so only the RST+ACK+data inject elicits the synthesized
    // RST. No FW1/FW2 prelude (CLOSING_03 stays in EST) and no verify-probe ACK (the positive's
    // CLOSED proof is the positive's concern; the negative only needs the synthesized RST). The
    // RST is injected with an in-window seq (snd_nxt) acking rcv_nxt, exactly as the positive.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        constexpr std::uint16_t kPortOffset = kTcpClosing03LocalOffset;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffset;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0 || !open.conn) return;
        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            silentlyCloseTesterFd(tester_fd);
            return;
        }

        // Per-phase arm after the handshake (the active-OPEN third-leg pure ACK is egress, and a
        // SYN,ACK carries no disruptive flag, so the gate would not trip on the handshake anyway;
        // arming here scopes it cleanly). The eliciting RST inject carries the arm settle so the
        // raw-injected arm lands first.
        emitIngressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpSynthRstOnDisruptive);

        ::tc8::stimulus::TcpSegmentSpec rst{};
        rst.src_port = remote_port;
        rst.dst_port = local_port;
        rst.seq_num  = seq_range->snd_nxt;   // in-window
        rst.ack_num  = seq_range->rcv_nxt;
        rst.flags    = ::tc8::stimulus::kTcpFlagRst | ::tc8::stimulus::kTcpFlagAck;
        rst.payload.assign(kRstPayloadLen, 0xA5U);
        emitTcpFrame(cfg, iface, cfg.dut.mac, rst, /*initial_wait=*/kFlavorArmSettle);

        std::this_thread::sleep_for(kSynthRstObserveHold);
        silentlyCloseTesterFd(tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpClosing03NegSM, tcp_closing_03_neg)
