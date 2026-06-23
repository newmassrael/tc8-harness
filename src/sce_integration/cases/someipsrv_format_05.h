#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_format_05_sm.h"

namespace tc8::sce::cases {

using Format05SM =
    ::SCE::Generated::someipsrv_format_05::someipsrv_format_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.1.5 — Message Type shall be statically set to 0x02
// (NOTIFICATION).
template <>
struct TestCaseTraits<cases::Format05SM>
    : SomeIpSdOnlyBase<cases::Format05SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_FORMAT_05";
    static constexpr std::string_view kDescription =
        "Message Type shall be statically set to 0x02 (NOTIFICATION)";
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Format05SM, someipsrv_format_05)
