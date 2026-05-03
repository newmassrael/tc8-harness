#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_format_02_sm.h"

namespace tc8::sce::cases {

using Format02SM =
    ::SCE::Generated::someipsrv_format_02::someipsrv_format_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.1.2 — After SD init, Session ID shall be 0x0001.
template <>
struct TestCaseTraits<cases::Format02SM>
    : SomeIpAnyBase<cases::Format02SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_FORMAT_02";
    static constexpr std::string_view kSpecSection = "5.1.5.1.2";
    static constexpr std::string_view kDescription =
        "After SD init, Session ID shall be 0x0001";

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:            return "pass";
            case State::Fail_session_id: return "fail:session_id_not_0x0001";
            case State::Fail_timeout:    return "fail:no_notification_within_listen_window";
            default:                     return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Format02SM, someipsrv_format_02)
