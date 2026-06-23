#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_onwire_11_sm.h"

namespace tc8::sce::cases {

using Onwire11SM = ::SCE::Generated::someipsrv_onwire_11::someipsrv_onwire_11;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.6.11 — Normal Request/Response carries Return Code
// E_OK (0x00). Tester invokes echoUINT8; pass requires the matched
// Response carries return_code == 0x00. Sibling axis to ONWIRE_07
// (Message Type 0x00 → 0x80 on the same shape).
template <>
struct TestCaseTraits<cases::Onwire11SM> : SomeIpAnyBase<cases::Onwire11SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_ONWIRE_11";
    static constexpr std::string_view kDescription =
        "Method Response on a normal Request carries Return Code E_OK";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.payload = {0x42};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Onwire11SM, someipsrv_onwire_11)
