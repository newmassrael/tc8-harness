#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "arp_10_sm.h"

namespace tc8::sce::cases {

using Arp10SM = ::SCE::Generated::arp_10::arp_10;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp10SM>
    : ArpAnyBase<cases::Arp10SM> {
    static constexpr std::string_view kCaseId       = "ARP_10";
    static constexpr std::string_view kSpecSection  = "4.2.4.1";
    static constexpr std::string_view kDescription  =
        "ARP request Hardware Address Length field shall carry ETHERNET_ADDR_LEN (6)";
    // UT 0x02 egress-provocation stimulus — see arp_07.h.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitArpEgressProvocation(cfg, iface, cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp10SM, arp_10)
