#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_format_10_sm.h"

namespace tc8::sce::cases {

using Format10SM =
    ::SCE::Generated::someipsrv_format_10::someipsrv_format_10;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.1.10 — 24-bit Reserved field after SD Flags byte
// shall be 0x000000.
template <>
struct TestCaseTraits<cases::Format10SM>
    : SomeIpSdOnlyBase<cases::Format10SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_FORMAT_10";
    static constexpr std::string_view kSpecSection = "5.1.5.1.10";
    static constexpr std::string_view kDescription =
        "SD Reserved field (24 bits) shall be 0x000000";

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:               return "pass";
            case State::Fail_reserved_bits: return "fail:sd_reserved_bits_nonzero";
            case State::Fail_timeout:       return "fail:no_notification_within_listen_window";
            default:                        return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Format10SM, someipsrv_format_10)
