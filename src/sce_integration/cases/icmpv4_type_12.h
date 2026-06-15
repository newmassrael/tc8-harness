#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_runner.h"
#include "stimulus/icmpv4_builder.h"  // kIcmpTimestampOriginate

#include "icmpv4_type_12_sm.h"

namespace tc8::sce::cases {

using Icmpv4Type12SM = ::SCE::Generated::icmpv4_type_12::icmpv4_type_12;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Icmpv4Type12SM>
    : Icmpv4TypedBase<cases::Icmpv4Type12SM, std::uint8_t{14}> {
    static constexpr std::string_view kCaseId      = "ICMPv4_TYPE_12";
    static constexpr std::string_view kSpecSection = "4.3.3.2";
    static constexpr std::string_view kDescription =
        "ICMP Timestamp Reply echoes Identifier and Sequence Number "
        "fields verbatim from the Timestamp Request";

    // Same stimulus shape as TYPE_11: Timestamp Request (type=13) with
    // the Originate literal — Receive / Transmit zero, Identifier /
    // Sequence default to `kIcmpEchoId` / `kIcmpEchoSeq` via the
    // builder's struct in-class initialisers. SCXML guards on the
    // identifier / sequence fields rather than the timestamp slots.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::icmpv4::StimulusOverrides ov{};
        ov.icmp_type = static_cast<std::uint8_t>(13);
        ov.timestamp_originate = ::tc8::stimulus::kIcmpTimestampOriginate;
        ::tc8::sce::icmpv4::emitStimulus(cfg, iface, ov);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Icmpv4Type12SM, icmpv4_type_12)
