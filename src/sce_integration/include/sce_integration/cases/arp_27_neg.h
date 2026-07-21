#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_27_neg_sm.h"

namespace tc8::sce::cases {

using Arp27NegSM = ::SCE::Generated::arp_27_neg::arp_27_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp27NegSM>
    : ArpIngressFaultNegBase<cases::Arp27NegSM> {
    static constexpr std::string_view kCaseId      = "ARP_27_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_27: the lwIP kArpFaultReplyToDropFrame ingress "
        "flavor makes the DUT reply to a Request with an unknown Protocol Type "
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
        spec.proto_type = 0xFFFF;  // ARP_PROTOCOL_UNKNOWN
        ::tc8::stimulus::emitArpFromTester(iface, spec);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp27NegSM, arp_27_neg)
