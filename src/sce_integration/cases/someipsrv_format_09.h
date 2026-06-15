#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_format_09_sm.h"

namespace tc8::sce::cases {

using Format09SM =
    ::SCE::Generated::someipsrv_format_09::someipsrv_format_09;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.1.9 — Six flag bits other than Reboot/Unicast shall be
// '0'. Mask = 0x3F.
template <>
struct TestCaseTraits<cases::Format09SM>
    : SomeIpSdOnlyBase<cases::Format09SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_FORMAT_09";
    static constexpr std::string_view kSpecSection = "5.1.5.1.9";
    static constexpr std::string_view kDescription =
        "SD undefined flag bits (mask 0x3F) shall be '0'";
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Format09SM, someipsrv_format_09)
