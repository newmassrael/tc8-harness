#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_055_sm.h"

namespace tc8::sce::cases {

using SomeipEts055SM = ::SCE::Generated::someip_ets_055::someip_ets_055;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_055 — Length_smaller_than_8_Test. Tester
// sends echoUINT8 (METHOD-ID 0x0008) with SOME/IP Length header forced
// to 0x00000004 (claims 4 bytes follow, but Request ID alone is 8). Per
// PRS_SOMEIP_00042 the DUT must reject with MALFORMED_MESSAGE or
// ignore. Reuses ETS_001's lenient 4-path verdict pattern.
template <>
struct TestCaseTraits<cases::SomeipEts055SM> : SomeIpAnyBase<cases::SomeipEts055SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_055";
    static constexpr std::string_view kDescription =
        "SOME/IP Length < 8 — DUT must reject (MALFORMED_MESSAGE) or ignore";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0008;
        target.payload = {0x42};
        // Length = 4 — header claims 4 bytes follow Request ID, smaller
        // than the 8-byte minimum (Request ID itself is 8 bytes). Per
        // SOME/IP §4.1.5 Length must be at least 8.
        target.length_override = 0x00000004u;
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts055SM, someip_ets_055)
