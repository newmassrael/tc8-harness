#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_178_sm.h"

namespace tc8::sce::cases {

using SomeipEts178SM = ::SCE::Generated::someip_ets_178::someip_ets_178;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_178 — SubscribeEventgroup whose SOME/IP
// header carries a non-SD Method ID (canonical 0x8100). Per
// PRS_SOMEIPSD_00306 / 00307 / 00380 / 00393 the DUT must reject the
// message because it cannot be interpreted as valid SOME/IP-SD. Lenient
// verdict accepts silent ignore — vsomeip silent-drops at the SD-message
// dispatch gate when Method ID != 0x8100.
template <>
struct TestCaseTraits<cases::SomeipEts178SM> : SomeIpAnyBase<cases::SomeipEts178SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_178";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup with wrong SOME/IP Method ID — DUT Nacks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        params.target.eventgroup_id = 0x0002;
        params.session_id = 0x0001;
        // Method ID 0x0042 (arbitrary non-SD value, NOT 0x8100). vsomeip's
        // SD dispatcher gates on full Service+Method tuple (FFFF/8100); a
        // non-matching Method ID drops the frame at routing layer.
        params.method_id_override = std::uint16_t{0x0042};
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts178SM, someip_ets_178)
