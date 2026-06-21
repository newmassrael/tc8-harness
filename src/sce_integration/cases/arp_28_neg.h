#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_28_neg_sm.h"

namespace tc8::sce::cases {

using Arp28NegSM = ::SCE::Generated::arp_28_neg::arp_28_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp28NegSM>
    : ArpIngressFaultNegUdpBase<cases::Arp28NegSM> {
    static constexpr std::string_view kCaseId      = "ARP_28_NEG";
    static constexpr std::string_view kSpecSection = "4.2.4.2";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_28: the lwIP kArpFaultLearnFromDropFrame ingress "
        "flavor makes the DUT learn a malformed gratuitous Response (unknown "
        "proto_type) it must drop; a conformant DUT emits its own ARP Request";
    // Arm the ingress learn fault, inject the malformed gratuitous Response the
    // positive uses (the frame the DUT must drop), then provoke UDP egress.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kArpFaultLearnFromDropFrame);
        ::tc8::stimulus::ArpFrameSpec spec;
        spec.proto_type = 0xFFFF;  // ARP_PROTOCOL_UNKNOWN
        spec.opcode = 0x0002;      // Response
        spec.target_hw = ::tc8::stimulus::kEthBroadcast;
        spec.sender_ip_be = cfg.arp.tester_ip;
        spec.target_ip_be = cfg.arp.tester_ip;  // gratuitous: target_ip == sender_ip
        ::tc8::stimulus::emitArpFromTester(iface, spec);
        // Full provocation wait (mirrors the positive ARP_28): the gap lets the
        // ingress hook land the static entry before the UT-provoked UDP egress.
        emitArpEgressProvocation(cfg, iface, cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp28NegSM, arp_28_neg)
