#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_options_05_sm.h"

namespace tc8::sce::cases {

using Options05SM =
    ::SCE::Generated::someipsrv_options_05::someipsrv_options_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Options05SM>
    : SomeIpAnyBase<cases::Options05SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_OPTIONS_05";
    static constexpr std::string_view kDescription =
        "Second Reserved field of the IPv4 Endpoint Option shall be 0x00";
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Options05SM, someipsrv_options_05)
