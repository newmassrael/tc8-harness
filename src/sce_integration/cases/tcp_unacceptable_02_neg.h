#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_seam_passive_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/cases/tcp_unacceptable_02.h"  // SSOT for kOutOfWindowRstSeq
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_unacceptable_02_neg_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable02NegSM = ::SCE::Generated::tcp_unacceptable_02_neg::tcp_unacceptable_02_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.3 TCP_UNACCEPTABLE_02 (SYN-RECEIVED): a conformant DUT in
// SYN-RECEIVED silently drops an unacceptable (out-of-window) RST without changing state or
// replying (RFC 793 §3.4). kTcpSynthRstOnDisruptive makes the lwIP netif input hook synthesize
// the prohibited RST on the listen 4-tuple when that RST arrives (its RST flag trips the
// disruptive-union gate), and the case passes only when that synthesized RST is observed.
// lwIP-only (kCapIngressFault). A §4.8 must-not-respond case the ingress-synthesis seam reaches
// but the egress field-fault cannot — the conformant DUT emits no segment to corrupt.
template <>
struct TestCaseTraits<cases::TcpUnacceptable02NegSM>
    : TcpIngressFaultNegBase<cases::TcpUnacceptable02NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_UNACCEPTABLE_02_NEG";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_UNACCEPTABLE_02 (SYN-RECEIVED): the lwIP "
        "kTcpSynthRstOnDisruptive ingress flavor makes the DUT emit a RST to an unacceptable "
        "RST in SYN-RECEIVED; a conformant DUT stays silent";

    // Mirrors the positive's seam (passive LISTEN + tester SYN -> DUT SYN,ACK -> SYN-RECEIVED),
    // with the fault armed after the DUT SYN,ACK and before the out-of-window RST inject. The RST
    // is bare (no ACK), SEQ far outside the receive window, exactly as the positive sends it.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        const std::uint16_t listen_port = kBasicsListenPort;
        const std::uint16_t tester_port = kBasicsTesterPort;
        if (!driveSeamListen(dut, listen_port)) return;

        auto snippet = TcpFrameSnippet::forDutSynAck(cfg, iface, tester_port);

        ::tc8::stimulus::TcpSegmentSpec syn{};
        syn.src_port = tester_port;
        syn.dst_port = listen_port;
        syn.seq_num  = kTesterInitialSeq;
        syn.ack_num  = 0U;
        syn.flags    = ::tc8::stimulus::kTcpFlagSyn;
        emitTcpFrame(cfg, iface, cfg.dut.mac, syn);

        const auto synack = snippet.tryCapture(std::chrono::milliseconds(500));
        if (synack.has_value()) {
            emitIngressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpSynthRstOnDisruptive);
            ::tc8::stimulus::TcpSegmentSpec rst{};
            rst.src_port = tester_port;
            rst.dst_port = listen_port;
            // The positive's out-of-window RST SEQ, reused as the SSOT (far
            // outside the receive window so the DUT's tcp_check_req rejects it).
            rst.seq_num  = TestCaseTraits<cases::TcpUnacceptable02SM>::kOutOfWindowRstSeq;
            rst.ack_num  = 0U;
            rst.flags    = ::tc8::stimulus::kTcpFlagRst;
            emitTcpFrame(cfg, iface, cfg.dut.mac, rst, /*initial_wait=*/kFlavorArmSettle);
            std::this_thread::sleep_for(kSynthRstObserveHold);
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable02NegSM, tcp_unacceptable_02_neg)
