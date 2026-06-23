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
    : SomeIpSdOnlyBase<cases::Format02SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_FORMAT_02";
    static constexpr std::string_view kDescription =
        "After SD init, Session ID shall be 0x0001";
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Format02SM, someipsrv_format_02)
