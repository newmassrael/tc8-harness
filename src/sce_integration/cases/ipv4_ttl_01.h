#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_ttl_01_sm.h"

namespace tc8::sce::cases {

using Ipv4Ttl01SM = ::SCE::Generated::ipv4_ttl_01::ipv4_ttl_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Ttl01SM>
    : Ipv4ObservationBase<cases::Ipv4Ttl01SM> {
    static constexpr std::string_view kCaseId      = "IPV4_TTL_01";
    static constexpr std::string_view kSpecSection = "4.4.4.3";
    static constexpr std::string_view kDescription =
        "DUT's ICMP Echo Reply carries an IPv4 header whose TTL field "
        "is greater than zero (RFC 1122 section 3.2.1.7)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::ipv4::emitStimulus(cfg, iface);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:         return "pass";
            case State::Fail_ttl:     return "fail:ipv4_ttl_is_zero";
            case State::Fail_timeout: return "fail:no_dut_ipv4_packet_within_listen_window";
            default:                  return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Ttl01SM, ipv4_ttl_01)
