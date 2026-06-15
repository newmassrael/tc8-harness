#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "icmpv4_type_10_sm.h"

namespace tc8::sce::cases {

using Icmpv4Type10SM = ::SCE::Generated::icmpv4_type_10::icmpv4_type_10;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Icmpv4Type10SM>
    : Icmpv4TypedBase<cases::Icmpv4Type10SM, std::uint8_t{0}> {
    static constexpr std::string_view kCaseId      = "ICMPv4_TYPE_10";
    static constexpr std::string_view kSpecSection = "4.3.3.2";
    static constexpr std::string_view kDescription =
        "ICMP checksum is checked — DUT sends no Echo Reply for a "
        "malformed Echo Request";

    // Build the same Echo Request as TYPE_09, but flip one bit of the
    // ICMP checksum so the DUT kernel silently discards it per
    // RFC 1122. A conformant DUT must not reply — the SCXML template
    // asserts absence via the `deadline_exceeded` path.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::icmpv4::StimulusOverrides ov{};
        ov.corrupt_icmp_checksum = true;
        ::tc8::sce::icmpv4::emitStimulus(cfg, iface, ov);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Icmpv4Type10SM, icmpv4_type_10)
