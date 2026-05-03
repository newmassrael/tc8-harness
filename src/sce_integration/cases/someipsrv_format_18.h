#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_format_18_sm.h"

namespace tc8::sce::cases {

using Format18SM =
    ::SCE::Generated::someipsrv_format_18::someipsrv_format_18;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.1.18 — Entry Minor Version shall carry the configured
// SERVICE-ID-1-MINOR-VER. Configured identity supplied at runtime via
// --expect minor_version=<n>.
template <>
struct TestCaseTraits<cases::Format18SM>
    : SomeIpSdOnlyBase<cases::Format18SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_FORMAT_18";
    static constexpr std::string_view kSpecSection = "5.1.5.1.18";
    static constexpr std::string_view kDescription =
        "Type 1 entry Minor Version shall carry the configured SERVICE-ID-1-MINOR-VER";

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:               return "pass";
            case State::Fail_minor_version: return "fail:entry_minor_version_mismatch";
            case State::Fail_timeout:       return "fail:no_notification_within_listen_window";
            default:                        return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Format18SM, someipsrv_format_18)
