#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_format_03_sm.h"

namespace tc8::sce::cases {

using Format03SM =
    ::SCE::Generated::someipsrv_format_03::someipsrv_format_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.1.3 — Protocol Version shall be statically set to 0x01.
template <>
struct TestCaseTraits<cases::Format03SM>
    : SomeIpSdOnlyBase<cases::Format03SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_FORMAT_03";
    static constexpr std::string_view kDescription =
        "Protocol Version shall be statically set to 0x01";
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Format03SM, someipsrv_format_03)
