#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_16_sm.h"

namespace tc8::sce::cases {

using Arp16SM = ::SCE::Generated::arp_16::arp_16;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp16SM>
    : ArpAnyBase<cases::Arp16SM> {
    static constexpr std::string_view kCaseId = "ARP_16";
    static constexpr std::string_view kSpecSection = "4.2.4.2";
    static constexpr std::string_view kDescription =
        "ARP Request reception with target_hw zero — DUT must reply because "
        "target_hw is the field being resolved";
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg, std::string_view iface) {
        ::tc8::stimulus::ArpFrameSpec spec;
        spec.sender_ip_be = cfg.arp.tester_ip;
        spec.target_ip_be = cfg.dut.ip;
        // target_hw stays at default kEthZero — the §4.2.4.2 ARP_16 variant.
        ::tc8::stimulus::emitArpFromTester(iface, spec);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp16SM, arp_16)
