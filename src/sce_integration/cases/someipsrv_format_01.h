#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

// Generated from tests/someipsrv_format_01.scxml by sce_add_state_machine().
#include "someipsrv_format_01_sm.h"

namespace tc8::sce::cases {

using Format01SM =
    ::SCE::Generated::someipsrv_format_01::someipsrv_format_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.1.1 — Client ID shall be set statically to 0x0000.
template <>
struct TestCaseTraits<cases::Format01SM>
    : SomeIpSdOnlyBase<cases::Format01SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_FORMAT_01";
    static constexpr std::string_view kDescription =
        "Client ID shall be set statically to 0x0000";
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Format01SM, someipsrv_format_01)
