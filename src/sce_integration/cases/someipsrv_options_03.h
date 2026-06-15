#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_options_03_sm.h"

namespace tc8::sce::cases {

using Options03SM =
    ::SCE::Generated::someipsrv_options_03::someipsrv_options_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Options03SM>
    : SomeIpAnyBase<cases::Options03SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_OPTIONS_03";
    static constexpr std::string_view kSpecSection = "5.1.5.5.3";
    static constexpr std::string_view kDescription =
        "First Reserved field of the IPv4 Endpoint Option shall be 0x00";
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Options03SM, someipsrv_options_03)
