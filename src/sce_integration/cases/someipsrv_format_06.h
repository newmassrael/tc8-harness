#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_format_06_sm.h"

namespace tc8::sce::cases {

using Format06SM =
    ::SCE::Generated::someipsrv_format_06::someipsrv_format_06;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.1.6 — Return Code shall be statically set to 0x00 for
// SD messages.
template <>
struct TestCaseTraits<cases::Format06SM>
    : SomeIpSdOnlyBase<cases::Format06SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_FORMAT_06";
    static constexpr std::string_view kSpecSection = "5.1.5.1.6";
    static constexpr std::string_view kDescription =
        "Return Code shall be statically set to 0x00 (SD messages)";

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:             return "pass";
            case State::Fail_return_code: return "fail:return_code_not_0x00";
            case State::Fail_timeout:     return "fail:no_notification_within_listen_window";
            default:                      return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Format06SM, someipsrv_format_06)
