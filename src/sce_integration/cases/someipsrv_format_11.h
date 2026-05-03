#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_format_11_sm.h"

namespace tc8::sce::cases {

using Format11SM =
    ::SCE::Generated::someipsrv_format_11::someipsrv_format_11;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.1.11 — Type 1 entry shape: entry type 0x01
// (OfferService) and entries-array length == NumberOfEntries * 16.
template <>
struct TestCaseTraits<cases::Format11SM>
    : SomeIpSdOnlyBase<cases::Format11SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_FORMAT_11";
    static constexpr std::string_view kSpecSection = "5.1.5.1.11";
    static constexpr std::string_view kDescription =
        "Type 1 entry type 0x01, entries array multiple of 16 bytes";

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:             return "pass";
            case State::Fail_entry_shape: return "fail:entry_type_or_length_unexpected";
            case State::Fail_timeout:     return "fail:no_notification_within_listen_window";
            default:                      return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Format11SM, someipsrv_format_11)
