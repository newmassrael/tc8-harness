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

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Version04SM>
    : Ipv4ObservationBase<cases::Ipv4Version04SM> {
    static constexpr std::string_view kCaseId      = "IPV4_VERSION_04";
    static constexpr std::string_view kSpecSection = "4.4.4.4";
    static constexpr std::string_view kDescription =
        "DUT silently discards an IPv4 packet whose Version field "
        "is other than 4";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::ipv4::StimulusOverrides ov{};
        ov.version = std::uint8_t{6};  // wire Version != 4, IHL stays 5
        ::tc8::sce::ipv4::emitStimulus(cfg, iface, ov);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:              return "pass";
            case State::Fail_dut_replied:  return "fail:dut_replied_despite_non_version_4";
            default:                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Version04SM, ipv4_version_04)
