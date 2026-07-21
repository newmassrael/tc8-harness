#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "arp_08_sm.h"

namespace tc8::sce::cases {

using Arp08SM = ::SCE::Generated::arp_08::arp_08;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp08SM>
    : ArpAnyBase<cases::Arp08SM> {
    static constexpr std::string_view kCaseId       = "ARP_08";
    static constexpr std::string_view kDescription  =
        "ARP request Hardware Type field shall carry ARP_HARDWARE_ETHERNET (0x0001)";
    // UT 0x02 egress-provocation stimulus — see arp_07.h.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitArpEgressProvocation(cfg, iface, cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp08SM, arp_08)
