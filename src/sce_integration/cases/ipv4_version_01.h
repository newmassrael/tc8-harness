#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_version_01_sm.h"

namespace tc8::sce::cases {

using Ipv4Version01SM = ::SCE::Generated::ipv4_version_01::ipv4_version_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Version01SM>
    : Ipv4ObservationBase<cases::Ipv4Version01SM> {
    static constexpr std::string_view kCaseId      = "IPV4_VERSION_01";
    static constexpr std::string_view kSpecSection = "4.4.4.4";
    static constexpr std::string_view kDescription =
        "DUT accepts an ICMPv4 Echo Request whose IPv4 header carries "
        "Version=4 (RFC 791 section 3.1, RFC 1122 section 3.2.1.1)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        // No override — the pilot default already sends Version=4.
        ::tc8::sce::ipv4::emitStimulus(cfg, iface);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:         return "pass";
            case State::Fail_timeout: return "fail:no_dut_ipv4_packet_with_expected_source_address";
            default:                  return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Version01SM, ipv4_version_01)
