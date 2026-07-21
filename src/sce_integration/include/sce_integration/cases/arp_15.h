#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "arp_15_sm.h"

namespace tc8::sce::cases {

using Arp15SM = ::SCE::Generated::arp_15::arp_15;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp15SM>
    : ArpAnyBase<cases::Arp15SM> {
    static constexpr std::string_view kCaseId       = "ARP_15";
    static constexpr std::string_view kDescription  =
        "ARP request Destination IP Address shall carry the resolution target IPv4";
    // UT 0x02 egress-provocation stimulus — see arp_07.h.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitArpEgressProvocation(cfg, iface, cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp15SM, arp_15)
