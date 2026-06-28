#pragma once

#include <chrono>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_100_sm.h"

namespace tc8::sce::cases {

using SomeipEts100SM = ::SCE::Generated::someip_ets_100::someip_ets_100;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_100 — SD_ClientServiceActivate_no_FindServices_
// in_Main_Phase. Per PRS_SOMEIPSD_00351 the DUT must emit FindService for the
// client-side target during the Start-Up Phase only; the Main Phase carries
// no client-side FindService. The DUT's `ClientModeRunner` realises this by
// emitting a Repetition-Phase burst (kRepetitionsMax+1 = 4 emits over
// ~1.5 s wall-clock) then idling. The verdict bisects the Start vs Main
// halves with a 4-state SCXML: phase 1 server warm-up → phase 2 first
// FindService → phase 3 burst-window absorption (3 s) → phase 4 absence
// window (4 s).
//
// Stimulus chain mirrors ETS_099: emitFindServiceBoot kicks vsomeip,
// emitMethodRequestAfter sends `clientServiceActivate` Fire&Forget. The
// DUT-side runner takes care of the Start-Up Phase / Main Phase transition
// from ets_impl's clientServiceActivate dispatch.
template <>
struct TestCaseTraits<cases::SomeipEts100SM> : SomeIpAnyBase<cases::SomeipEts100SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_100";
    static constexpr std::string_view kDescription =
        "Client-mode FindService is bounded to Start-Up Phase, absent in Main Phase";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::SomeIpRpcMessage target{};
        target.method_id    = 0x002F;        // clientServiceActivate
        target.message_type = ::tc8::someip::MessageType::REQUEST_NO_RETURN;          // Fire&Forget
        target.payload      = {0x00};        // delay = 0
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts100SM, someip_ets_100)
