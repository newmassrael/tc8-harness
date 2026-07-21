#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_37_neg_sm.h"

namespace tc8::sce::cases {

using Arp37NegSM = ::SCE::Generated::arp_37_neg::arp_37_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp37NegSM>
    : ArpIngressFaultNegBase<cases::Arp37NegSM> {
    static constexpr std::string_view kCaseId      = "ARP_37_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_37: the lwIP kArpFaultReplyToDropFrame ingress "
        "flavor makes the DUT reply to a Request whose Target Protocol Address is "
        "not the DUT's IP (which it must drop); a conformant DUT stays silent";
    // Arm the ingress reply fault, then inject the foreign-target Request the
    // positive uses (the frame the DUT must drop without replying).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kArpFaultReplyToDropFrame);
        ::tc8::stimulus::ArpFrameSpec spec;
        spec.sender_ip_be = cfg.arp.tester_ip;
        // 10.99.99.99 in network byte order: 0x0A 0x63 0x63 0x63 (a /24 host not
        // bound to the DUT or tester) — mirrors the positive ARP_37 stimulus.
        spec.target_ip_be = 0x6363630Au;
        ::tc8::stimulus::emitArpFromTester(iface, spec);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp37NegSM, arp_37_neg)
