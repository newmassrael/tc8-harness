#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_onwire_10_sm.h"

namespace tc8::sce::cases {

using Onwire10SM = ::SCE::Generated::someipsrv_onwire_10::someipsrv_onwire_10;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.6.10 — UNKNOWN-SERVICE-ID Request elicits
// SOMEIP_MSG_TYPE_ERROR with return_code == E_UNKNOWN_SERVICE (0x02).
// Tester sends a Request whose service_id is the kServiceId sentinel
// (0xFFFE); pass requires the matched Error echoes the unknown
// service_id AND return_code == 0x02.
template <>
struct TestCaseTraits<cases::Onwire10SM> : SomeIpAnyBase<cases::Onwire10SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_ONWIRE_10";
    static constexpr std::string_view kSpecSection = "5.1.5.6.10";
    static constexpr std::string_view kDescription =
        "Error message for UNKNOWN-SERVICE-ID Request carries return_code E_UNKNOWN_SERVICE";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.service_id = ::tc8::sd_test_unknown::kServiceId;
        target.payload = {0x42};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Onwire10SM, someipsrv_onwire_10)
