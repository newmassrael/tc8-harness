#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_054_sm.h"

namespace tc8::sce::cases {

using SomeipEts054SM = ::SCE::Generated::someip_ets_054::someip_ets_054;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_054 — Length_equals_0_Test. Tester sends
// echoUINT8 (METHOD-ID 0x0008) with SOME/IP Length header forced to
// 0x00000000. Per PRS_SOMEIP_00042 the DUT must reject with
// MALFORMED_MESSAGE or ignore. Reuses ETS_001's lenient 4-path verdict
// pattern (Error Response, non-zero return_code, or silent ignore;
// only normal echo with return_code 0x00 lands on fail).
template <>
struct TestCaseTraits<cases::SomeipEts054SM> : SomeIpAnyBase<cases::SomeipEts054SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_054";
    static constexpr std::string_view kDescription =
        "SOME/IP Length = 0 — DUT must reject (MALFORMED_MESSAGE) or ignore";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0008;
        target.payload = {0x42};
        // Length = 0 — header claims no bytes follow Request ID. Valid
        // SOME/IP Length is at least 8 (Request ID alone is 8 bytes), so
        // Length 0 is a malformed-frame axis.
        target.length_override = 0x00000000u;
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts054SM, someip_ets_054)
