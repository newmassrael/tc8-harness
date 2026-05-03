#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_options_05_sm.h"

namespace tc8::sce::cases {

using Options05SM =
    ::SCE::Generated::someipsrv_options_05::someipsrv_options_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Options05SM>
    : SomeIpAnyBase<cases::Options05SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_OPTIONS_05";
    static constexpr std::string_view kSpecSection = "5.1.5.5.5";
    static constexpr std::string_view kDescription =
        "Second Reserved field of the IPv4 Endpoint Option shall be 0x00";

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:           return "pass";
            case State::Fail_reserved2: return "fail:ipv4_endpoint_second_reserved_nonzero";
            case State::Fail_timeout:   return "fail:no_qualifying_sd_message_within_listen_window";
            default:                    return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Options05SM, someipsrv_options_05)
