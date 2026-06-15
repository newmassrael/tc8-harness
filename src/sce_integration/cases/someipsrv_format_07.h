#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_format_07_sm.h"

namespace tc8::sce::cases {

using Format07SM =
    ::SCE::Generated::someipsrv_format_07::someipsrv_format_07;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.1.7 — Reboot Flag shall be '1' for first SD messages
// after reboot (until Session ID wraps).
template <>
struct TestCaseTraits<cases::Format07SM>
    : SomeIpSdOnlyBase<cases::Format07SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_FORMAT_07";
    static constexpr std::string_view kSpecSection = "5.1.5.1.7";
    static constexpr std::string_view kDescription =
        "SD Reboot Flag shall be '1' after reboot";
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Format07SM, someipsrv_format_07)
