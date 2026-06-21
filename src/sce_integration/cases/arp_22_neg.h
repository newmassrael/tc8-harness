#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_22_neg_sm.h"

namespace tc8::sce::cases {

using Arp22NegSM = ::SCE::Generated::arp_22_neg::arp_22_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp22NegSM>
    : ArpFaultNegUdpBase<cases::Arp22NegSM> {
    static constexpr std::string_view kCaseId      = "ARP_22_NEG";
    static constexpr std::string_view kSpecSection = "4.2.4.2";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_22: the lwIP kArpFaultLearnFromDropFrame ingress "
        "flavor makes the DUT learn a malformed gratuitous Response (unknown "
        "hw_type) it must drop; a conformant DUT emits its own ARP Request";
    // Arm the ingress learn fault, inject the malformed gratuitous Response the
    // positive uses (the frame the DUT must drop), then provoke UDP egress.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitArpFlavorArm(cfg, iface, ::tc8::ut::kArpFaultLearnFromDropFrame);
        ::tc8::stimulus::ArpFrameSpec spec;
        spec.hw_type = 0xFFFF;  // ARP_HARDWARE_TYPE_UNKNOWN
        spec.opcode = 0x0002;   // Response
        spec.target_hw = ::tc8::stimulus::kEthBroadcast;
        spec.sender_ip_be = cfg.arp.tester_ip;
        spec.target_ip_be = cfg.arp.tester_ip;  // gratuitous: target_ip == sender_ip
        ::tc8::stimulus::emitArpFromTester(iface, spec);
        // Full provocation wait (mirrors the positive ARP_22): the gap lets the
        // ingress hook land the static entry before the UT-provoked UDP egress.
        emitArpEgressProvocation(cfg, iface, cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp22NegSM, arp_22_neg)
