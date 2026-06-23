#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_076_sm.h"

namespace tc8::sce::cases {

using SomeipEts076SM = ::SCE::Generated::someip_ets_076::someip_ets_076;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_076 — Wrong_Method_ID.
// Tester sends Method Request with method_id 0x00FF (unassigned per
// TC8 §5.1.4 Table 1). ETS_001-style lenient 4-path verdict; cond
// watches Method 0x00FF (not 0x0008) so an echoed 0x0008 reply
// (impossible) can't trivially pass.
template <>
struct TestCaseTraits<cases::SomeipEts076SM> : SomeIpAnyBase<cases::SomeipEts076SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_076";
    static constexpr std::string_view kDescription =
        "Wrong Method ID (0x00FF unknown) — DUT must reject or ignore";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x00FF;  // Unassigned per TC8 §5.1.4 Table 1
        target.payload = {0x42};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts076SM, someip_ets_076)
