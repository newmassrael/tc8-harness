#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_format_04_sm.h"

namespace tc8::sce::cases {

using Format04SM =
    ::SCE::Generated::someipsrv_format_04::someipsrv_format_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.1.4 — Interface Version shall be statically set to 0x01.
template <>
struct TestCaseTraits<cases::Format04SM>
    : SomeIpAnyBase<cases::Format04SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_FORMAT_04";
    static constexpr std::string_view kSpecSection = "5.1.5.1.4";
    static constexpr std::string_view kDescription =
        "Interface Version shall be statically set to 0x01";

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                   return "pass";
            case State::Fail_interface_version: return "fail:interface_version_not_0x01";
            case State::Fail_timeout:           return "fail:no_notification_within_listen_window";
            default:                            return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Format04SM, someipsrv_format_04)
