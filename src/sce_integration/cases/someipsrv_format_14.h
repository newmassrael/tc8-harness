#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_format_14_sm.h"

namespace tc8::sce::cases {

using Format14SM =
    ::SCE::Generated::someipsrv_format_14::someipsrv_format_14;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.1.14 — Entry Service ID shall carry SERVICE-ID-1.
// Configured identity supplied at runtime via --expect service_id=<hex>.
template <>
struct TestCaseTraits<cases::Format14SM>
    : SomeIpSdOnlyBase<cases::Format14SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_FORMAT_14";
    static constexpr std::string_view kSpecSection = "5.1.5.1.14";
    static constexpr std::string_view kDescription =
        "Type 1 entry Service ID shall carry the configured SERVICE-ID-1";

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:            return "pass";
            case State::Fail_service_id: return "fail:entry_service_id_mismatch";
            case State::Fail_timeout:    return "fail:no_notification_within_listen_window";
            default:                     return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Format14SM, someipsrv_format_14)
