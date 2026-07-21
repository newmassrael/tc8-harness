#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "arp_14_sm.h"

namespace tc8::sce::cases {

using Arp14SM = ::SCE::Generated::arp_14::arp_14;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp14SM>
    : ArpAnyBase<cases::Arp14SM> {
    static constexpr std::string_view kCaseId       = "ARP_14";
    static constexpr std::string_view kDescription  =
        "ARP request Source IP Address shall carry the configured DIface-0 IPv4";
    // UT 0x02 egress-provocation stimulus — see arp_07.h.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitArpEgressProvocation(cfg, iface, cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp14SM, arp_14)
