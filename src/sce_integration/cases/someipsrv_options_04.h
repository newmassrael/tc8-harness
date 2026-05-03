#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_options_04_sm.h"

namespace tc8::sce::cases {

using Options04SM =
    ::SCE::Generated::someipsrv_options_04::someipsrv_options_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Options04SM>
    : SomeIpAnyBase<cases::Options04SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_OPTIONS_04";
    static constexpr std::string_view kSpecSection = "5.1.5.5.4";
    static constexpr std::string_view kDescription =
        "IPv4-Address field of the IPv4 Endpoint Option shall be the local IP";

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:         return "pass";
            case State::Fail_ipv4:    return "fail:ipv4_endpoint_address_not_dut_iface_ip";
            case State::Fail_timeout: return "fail:no_qualifying_sd_message_within_listen_window";
            default:                  return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Options04SM, someipsrv_options_04)
