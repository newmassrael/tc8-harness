#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_21_neg_sm.h"

namespace tc8::sce::cases {

using Arp21NegSM = ::SCE::Generated::arp_21_neg::arp_21_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp21NegSM>
    : ArpIngressFaultNegBase<cases::Arp21NegSM> {
    static constexpr std::string_view kCaseId      = "ARP_21_NEG";
    static constexpr std::string_view kSpecSection = "4.2.4.2";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_21: the lwIP kArpFaultReplyToDropFrame ingress "
        "flavor makes the DUT reply to a Request with an unknown Hardware Type "
        "(which it must drop); a conformant DUT stays silent";
    // Arm the ingress reply fault, then inject the malformed Request the positive
    // uses (the frame the DUT must drop without replying).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kArpFaultReplyToDropFrame);
        ::tc8::stimulus::ArpFrameSpec spec;
        spec.sender_ip_be = cfg.arp.tester_ip;
        spec.target_ip_be = cfg.dut.ip;
        spec.hw_type = 0xFFFF;  // ARP_HARDWARE_TYPE_UNKNOWN
        ::tc8::stimulus::emitArpFromTester(iface, spec);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp21NegSM, arp_21_neg)
