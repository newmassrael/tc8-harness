#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_options_06_sm.h"

namespace tc8::sce::cases {

using Options06SM =
    ::SCE::Generated::someipsrv_options_06::someipsrv_options_06;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Options06SM>
    : SomeIpAnyBase<cases::Options06SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_OPTIONS_06";
    static constexpr std::string_view kSpecSection = "5.1.5.5.6";
    static constexpr std::string_view kDescription =
        "Layer-4 Protocol field of the IPv4 Endpoint Option for UDP shall be 0x11";

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:         return "pass";
            case State::Fail_l4_udp:  return "fail:no_ipv4_endpoint_option_with_udp_l4";
            case State::Fail_timeout: return "fail:no_qualifying_sd_message_within_listen_window";
            default:                  return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Options06SM, someipsrv_options_06)
