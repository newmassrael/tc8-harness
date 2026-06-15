#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_ttl_05_sm.h"

namespace tc8::sce::cases {

using Ipv4Ttl05SM = ::SCE::Generated::ipv4_ttl_05::ipv4_ttl_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Ttl05SM>
    : Ipv4ObservationBase<cases::Ipv4Ttl05SM> {
    static constexpr std::string_view kCaseId      = "IPv4_TTL_05";
    static constexpr std::string_view kSpecSection = "4.4.4.3";
    static constexpr std::string_view kDescription =
        "DUT replies to an ICMPv4 Echo Request carrying TTL=0 (RFC 1122 "
        "section 3.2.1.7: host MUST NOT discard on TTL < 2)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::ipv4::StimulusOverrides ov{};
        ov.ttl = std::uint8_t{0};
        ::tc8::sce::ipv4::emitStimulus(cfg, iface, ov);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Ttl05SM, ipv4_ttl_05)
