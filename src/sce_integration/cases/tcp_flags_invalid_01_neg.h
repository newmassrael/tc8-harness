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

#include "tcp_flags_invalid_01_neg_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid01NegSM = ::SCE::Generated::tcp_flags_invalid_01_neg::tcp_flags_invalid_01_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.6 TCP_FLAGS_INVALID_01 (LISTEN): a conformant DUT in LISTEN drops an
// incoming SYN+RST without any reply and stays in LISTEN (RFC 793 §3.9 — RST takes precedence).
// kTcpSynthRstOnDisruptive makes the lwIP netif input hook synthesize the prohibited RST on the
// SYN+RST 4-tuple when that segment arrives, and the case passes only when that synthesized RST
// is observed. lwIP-only (kCapIngressFault). A §4.8 must-not-respond case the ingress-synthesis
// seam reaches but the egress field-fault cannot — the conformant DUT emits no segment to corrupt.
template <>
struct TestCaseTraits<cases::TcpFlagsInvalid01NegSM>
    : TcpIngressFaultNegBase<cases::TcpFlagsInvalid01NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_INVALID_01_NEG";
    static constexpr std::string_view kSpecSection  = "4.8.6.6";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_FLAGS_INVALID_01 (LISTEN): the lwIP kTcpSynthRstOnDisruptive "
        "ingress flavor makes the DUT emit a RST to a SYN+RST received in LISTEN; a conformant "
        "DUT stays silent";

    // Mirrors the positive's LISTEN seam: a baseline bare SYN draws the DUT SYN,ACK (proving the
    // listen socket is live), then the spec-asserted SYN+RST is injected on a distinct tester
    // source port (+1, as the positive does, so the baseline's SYN-RECEIVED retransmits stay off
    // the watched 4-tuple). The fault is armed after the baseline SYN,ACK and before the SYN+RST
    // so only the SYN+RST elicits the synthesized RST. TesterAutoRstDrop suppresses the tester
    // kernel's RST to the raw-injected baseline SYN,ACK (it has no socket for it).
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

        // Baseline: bare SYN on the listen 4-tuple draws the DUT SYN,ACK (precondition confirm).
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

            // Spec-asserted SYN+RST on a distinct tester source port; the conformant DUT drops it
            // in LISTEN, so the synthesized RST (on this same 4-tuple) is the only DUT segment the
            // watch can match.
            ::tc8::stimulus::TcpSegmentSpec syn_rst{};
            syn_rst.src_port = tester_port + 1U;
            syn_rst.dst_port = listen_port;
            syn_rst.seq_num  = kTesterInitialSeq;
            syn_rst.ack_num  = 0U;
            syn_rst.flags    = ::tc8::stimulus::kTcpFlagSyn | ::tc8::stimulus::kTcpFlagRst;
            emitTcpFrame(cfg, iface, cfg.dut.mac, syn_rst, /*initial_wait=*/kFlavorArmSettle);
            std::this_thread::sleep_for(kSynthRstObserveHold);
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid01NegSM, tcp_flags_invalid_01_neg)
