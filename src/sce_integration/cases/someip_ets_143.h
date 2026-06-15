#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_143_sm.h"

namespace tc8::sce::cases {

using SomeipEts143SM = ::SCE::Generated::someip_ets_143::someip_ets_143;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_143 — SubscribeEventgroup whose Service-ID
// (0x9999) is not offered by the DUT (canonical SERVICE-ID-1 = 0xF4E7).
// Per PRS_SOMEIPSD_00386 / 00394 / 00393 the DUT must Nack. Lenient
// verdict accepts silent ignore — vsomeip's routing manager
// silent-drops at the routing layer before any Nack can dispatch.
template <>
struct TestCaseTraits<cases::SomeipEts143SM> : SomeIpAnyBase<cases::SomeipEts143SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_143";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup with non-existing Service-ID — DUT Nacks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        params.target.service_id = 0x9999;
        params.target.eventgroup_id = 0x0002;
        params.session_id = 0x0001;
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts143SM, someip_ets_143)
