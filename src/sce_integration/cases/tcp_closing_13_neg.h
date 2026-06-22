#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_closing_13_neg_sm.h"

namespace tc8::sce::cases {

using TcpClosing13NegSM = ::SCE::Generated::tcp_closing_13_neg::tcp_closing_13_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.8 TCP_CLOSING_13 (CLOSED): a conformant DUT drops a bare RST sent to
// a port with no socket without any reply (RFC 793 §3.9 — an incoming RST is discarded).
// kTcpSynthRstOnDisruptive makes the lwIP netif input hook synthesize the prohibited RST on the
// closed-port 4-tuple when that bare RST arrives, and the case passes only when that synthesized
// RST is observed. lwIP-only (kCapIngressFault). A §4.8 must-not-respond case the ingress-
// synthesis seam reaches but the egress field-fault cannot — the conformant DUT emits no segment
// to corrupt.
//
// No connection on either side, so there is no handshake to scope the arm past: the flavor is
// armed before the single bare-RST inject (no seam, no kernel state — same minimal shape as the
// positive, which only raw-injects the RST and observes silence). The synthesized RST is
// DUT-sourced (src = DUT netif IP, src port = the closed dst port the trigger targeted), matching
// is_dut_rst on (kBasicsClosedPort, kBasicsTesterPort + 80).
template <>
struct TestCaseTraits<cases::TcpClosing13NegSM>
    : TcpIngressFaultNegBase<cases::TcpClosing13NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_CLOSING_13_NEG";
    static constexpr std::string_view kSpecSection  = "4.8.6.8";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_CLOSING_13 (CLOSED): the lwIP kTcpSynthRstOnDisruptive ingress "
        "flavor makes the DUT emit a RST to a bare RST received on a closed port; a conformant "
        "DUT stays silent";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // Arm before the inject; the eliciting RST carries the arm settle so the raw-injected arm
        // lands first.
        emitIngressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpSynthRstOnDisruptive);

        ::tc8::stimulus::TcpSegmentSpec rst{};
        rst.src_port = kBasicsTesterPort + 80U;
        rst.dst_port = kBasicsClosedPort;
        rst.seq_num  = kTesterInitialSeq;
        rst.ack_num  = 0U;
        rst.flags    = ::tc8::stimulus::kTcpFlagRst;
        emitTcpFrame(cfg, iface, cfg.dut.mac, rst, /*initial_wait=*/kFlavorArmSettle);

        std::this_thread::sleep_for(kSynthRstObserveHold);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpClosing13NegSM, tcp_closing_13_neg)
