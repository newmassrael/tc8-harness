#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_format_08_sm.h"

namespace tc8::sce::cases {

using Format08SM =
    ::SCE::Generated::someipsrv_format_08::someipsrv_format_08;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.1.8 — Unicast Flag shall be '1' (DUT supports unicast).
template <>
struct TestCaseTraits<cases::Format08SM>
    : SomeIpSdOnlyBase<cases::Format08SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_FORMAT_08";
    static constexpr std::string_view kDescription =
        "SD Unicast Flag shall be '1'";
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Format08SM, someipsrv_format_08)
