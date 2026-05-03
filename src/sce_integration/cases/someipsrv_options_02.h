#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_options_02_sm.h"

namespace tc8::sce::cases {

using Options02SM =
    ::SCE::Generated::someipsrv_options_02::someipsrv_options_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Options02SM>
    : SomeIpAnyBase<cases::Options02SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_OPTIONS_02";
    static constexpr std::string_view kSpecSection = "5.1.5.5.2";
    static constexpr std::string_view kDescription =
        "Type field of the IPv4 Endpoint Option shall be 0x04";

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:         return "pass";
            case State::Fail_type:    return "fail:non_ipv4_endpoint_option_present_in_offer";
            case State::Fail_timeout: return "fail:no_qualifying_sd_message_within_listen_window";
            default:                  return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Options02SM, someipsrv_options_02)
