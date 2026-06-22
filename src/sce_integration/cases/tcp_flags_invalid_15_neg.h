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
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_invalid_15_neg_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid15NegSM = ::SCE::Generated::tcp_flags_invalid_15_neg::tcp_flags_invalid_15_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.6 TCP_FLAGS_INVALID_15 phase 1 (SYN-RECEIVED): a conformant DUT in
// SYN-RECEIVED silently drops an out-of-window RST (RFC 793 §3.9). kTcpSynthRstOnDisruptive makes
// the lwIP netif input hook synthesize the prohibited RST on the listen 4-tuple when the OTW RST
// arrives, and the case passes only when that synthesized RST is observed. lwIP-only
// (kCapIngressFault). One of the eight per-fail-final variants graduating the multi-guard positive.
template <>
struct TestCaseTraits<cases::TcpFlagsInvalid15NegSM>
    : TcpIngressFaultNegBase<cases::TcpFlagsInvalid15NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_INVALID_15_NEG";
    static constexpr std::string_view kSpecSection  = "4.8.6.6";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_FLAGS_INVALID_15 (SYN-RECEIVED): the lwIP "
        "kTcpSynthRstOnDisruptive ingress flavor makes the DUT emit a RST to an out-of-window "
        "RST in SYN-RECEIVED; a conformant DUT stays silent";

    // Mirrors the positive's phase-1 seam (passive LISTEN + tester SYN -> DUT SYN,ACK ->
    // SYN-RECEIVED), with the fault armed after the DUT SYN,ACK and before the OTW-RST inject.
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
            rst.seq_num  = kTesterInitialSeq + 1U + kOutOfWindowSeqOffset;
            rst.ack_num  = synack->seq_num + 1U;
            rst.flags    = ::tc8::stimulus::kTcpFlagRst | ::tc8::stimulus::kTcpFlagAck;
            emitTcpFrame(cfg, iface, cfg.dut.mac, rst, /*initial_wait=*/kFlavorArmSettle);
            std::this_thread::sleep_for(kSynthRstObserveHold);
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid15NegSM, tcp_flags_invalid_15_neg)
