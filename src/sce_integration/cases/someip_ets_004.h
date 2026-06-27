#pragma once

#include <chrono>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_004_sm.h"

namespace tc8::sce::cases {

using SomeipEts004SM = ::SCE::Generated::someip_ets_004::someip_ets_004;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_004 — DUT must respond to every request
// in a burst. Tester drives 3 echoUINT8 Method Requests at 50 ms
// cadence; SCXML phases 2a/2b/2c each verify a Method Response
// pinned by session_id (0x0001/0x0002/0x0003 — emitted by
// `emitMethodRequestAfter` with target.session_id default 0x0001
// + retry_interval 50 ms). A DUT that drops or coalesces responses
// trips one of the per-phase deadlines.
template <>
struct TestCaseTraits<cases::SomeipEts004SM> : SomeIpAnyBase<cases::SomeipEts004SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_004";
    static constexpr std::string_view kDescription =
        "Burst test — DUT must respond to each Method Request in a quick burst";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0008;
        target.payload = {0x42};
        ::tc8::stimulus::MethodRequestTiming timing{};
        // 3-Request burst at 50 ms cadence — quick enough that the
        // DUT must process them in parallel rather than back-to-back
        // serial echo. Spec body says "burst" without fixing N; 3
        // satisfies the invariant while keeping the SCXML phase
        // chain readable.
        timing.total_emits = 3;
        timing.retry_interval = std::chrono::milliseconds(50);
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, timing, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts004SM, someip_ets_004)
