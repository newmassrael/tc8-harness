#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_140_sm.h"

namespace tc8::sce::cases {

using SomeipEts140SM = ::SCE::Generated::someip_ets_140::someip_ets_140;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_140 — SubscribeEventgroup whose
// Eventgroup-ID (0x00FE) is not configured on the DUT (canonical
// configured set on tc8-dut SERVICE-ID-1: {0x0002, 0x0005, 0x0006,
// 0x0008}). Per PRS_SOMEIPSD_00394 / 00393 / 00566 the DUT must Nack.
// Lenient verdict accepts silent ignore — vsomeip's
// `process_eventgroupentry` logs "unknown eventgroup" and may
// silent-drop before its SD layer dispatches a Nack.
template <>
struct TestCaseTraits<cases::SomeipEts140SM> : SomeIpAnyBase<cases::SomeipEts140SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_140";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup with non-existing Eventgroup-ID — DUT Nacks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        // Pick an Eventgroup-ID that is clearly outside the configured
        // tc8-dut surface so the DUT cannot accidentally Ack.
        params.target.eventgroup_id = 0x00FE;
        params.session_id = 0x0001;
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts140SM, someip_ets_140)
