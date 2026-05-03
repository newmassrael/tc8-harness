#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_format_17_sm.h"

namespace tc8::sce::cases {

using Format17SM =
    ::SCE::Generated::someipsrv_format_17::someipsrv_format_17;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.1.17 — Entry TTL shall carry the configured
// SERVICE-ID-1-TTL. Configured identity supplied at runtime via
// --expect ttl=<n>.
template <>
struct TestCaseTraits<cases::Format17SM>
    : SomeIpSdOnlyBase<cases::Format17SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_FORMAT_17";
    static constexpr std::string_view kSpecSection = "5.1.5.1.17";
    static constexpr std::string_view kDescription =
        "Type 1 entry TTL shall carry the configured SERVICE-ID-1-TTL";

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:         return "pass";
            case State::Fail_ttl:     return "fail:entry_ttl_mismatch";
            case State::Fail_timeout: return "fail:no_notification_within_listen_window";
            default:                  return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Format17SM, someipsrv_format_17)
