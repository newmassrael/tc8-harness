#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "arp_12_sm.h"

namespace tc8::sce::cases {

using Arp12SM = ::SCE::Generated::arp_12::arp_12;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp12SM>
    : ArpAnyBase<cases::Arp12SM> {
    static constexpr std::string_view kCaseId       = "ARP_12";
    static constexpr std::string_view kDescription  =
        "ARP request Operation Code field shall carry OPERATION_REQUEST (1)";
    // UT 0x02 egress-provocation stimulus — see arp_07.h.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitArpEgressProvocation(cfg, iface, cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp12SM, arp_12)
