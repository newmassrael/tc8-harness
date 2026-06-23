#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_options_07_sm.h"

namespace tc8::sce::cases {

using Options07SM =
    ::SCE::Generated::someipsrv_options_07::someipsrv_options_07;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Options07SM>
    : SomeIpAnyBase<cases::Options07SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_OPTIONS_07";
    static constexpr std::string_view kDescription =
        "Port Number field of the IPv4 Endpoint Option shall carry the service UDP port";
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Options07SM, someipsrv_options_07)
