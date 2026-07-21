#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_version_04_sm.h"

namespace tc8::sce::cases {

using Ipv4Version04SM = ::SCE::Generated::ipv4_version_04::ipv4_version_04;

// §4.4.4.4 spec literal: wire Version != 4 (6, IHL stays 5) — a datagram a
// conformant DUT silently discards at its version check. SSOT shared by the
// positive stimulus and the IPv4_VERSION_04_NEG self-validation.
inline constexpr std::uint8_t kIpv4Version04BadVersion = 6U;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Version04SM>
    : Ipv4ObservationBase<cases::Ipv4Version04SM> {
    static constexpr std::string_view kCaseId      = "IPv4_VERSION_04";
    static constexpr std::string_view kDescription =
        "DUT silently discards an IPv4 packet whose Version field "
        "is other than 4";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::ipv4::StimulusOverrides ov{};
        ov.version = cases::kIpv4Version04BadVersion;
        ::tc8::sce::ipv4::emitStimulus(cfg, iface, ov);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Version04SM, ipv4_version_04)
