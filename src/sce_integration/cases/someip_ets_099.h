#pragma once

#include <chrono>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_099_sm.h"

namespace tc8::sce::cases {

using SomeipEts099SM = ::SCE::Generated::someip_ets_099::someip_ets_099;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_099 — SD_ClientServiceActivate. Tester invokes
// `clientServiceActivate` (Fire&Forget, MethodID 0x002F) on the DUT, which
// must transition into Client Mode while keeping Server Mode alive. The DUT
// firmware's `EtsImpl::clientServiceActivate` (dut/dut_service/ets_impl.cpp)
// spawns a `ClientModeRunner` (client_mode.cpp) that emits FindService for
// SERVICE-ID-2 (0xF4E8) on the SD multicast group during the Start-Up
// Phase. Phase 1 verifies Server Mode is still live (OfferService for
// SERVICE-ID-1); phase 2 verifies the new FindService stream arrives.
//
// Reference: PRS_SOMEIPSD_00350 / PRS_SOMEIPSD_00351.
template <>
struct TestCaseTraits<cases::SomeipEts099SM> : SomeIpAnyBase<cases::SomeipEts099SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_099";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "clientServiceActivate spawns FindService for SERVICE-ID-2 while preserving SERVICE-ID-1 server";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id    = 0x002F;        // clientServiceActivate per TC8 §5.1.4 Table 1.
        target.message_type = 0x01;          // RequestNoReturn (Fire&Forget) per ets.fidl.
        target.payload      = {0x00};        // delay byte = 0 — start immediately.
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts099SM, someip_ets_099)
