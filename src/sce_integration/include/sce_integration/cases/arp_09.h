#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "arp_09_sm.h"

namespace tc8::sce::cases {

using Arp09SM = ::SCE::Generated::arp_09::arp_09;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp09SM>
    : ArpAnyBase<cases::Arp09SM> {
    static constexpr std::string_view kCaseId       = "ARP_09";
    static constexpr std::string_view kDescription  =
        "ARP request Protocol Type field shall carry ARP_PROTOCOL_IP (0x0800)";
    // UT 0x02 egress-provocation stimulus — see arp_07.h.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitArpEgressProvocation(cfg, iface, cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp09SM, arp_09)
