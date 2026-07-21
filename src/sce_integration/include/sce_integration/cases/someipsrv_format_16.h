#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_format_16_sm.h"

namespace tc8::sce::cases {

using Format16SM =
    ::SCE::Generated::someipsrv_format_16::someipsrv_format_16;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.1.16 — Entry Major Version shall carry the configured
// SERVICE-ID-1-MAJ-VER. Configured identity supplied at runtime via
// --expect major_version=<n>.
template <>
struct TestCaseTraits<cases::Format16SM>
    : SomeIpSdOnlyBase<cases::Format16SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_FORMAT_16";
    static constexpr std::string_view kDescription =
        "Type 1 entry Major Version shall carry the configured SERVICE-ID-1-MAJ-VER";
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Format16SM, someipsrv_format_16)
