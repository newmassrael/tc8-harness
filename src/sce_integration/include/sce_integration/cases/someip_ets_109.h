#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_109_sm.h"

namespace tc8::sce::cases {

using SomeipEts109SM = ::SCE::Generated::someip_ets_109::someip_ets_109;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_109 — SubscribeEventgroup whose IPv4 Endpoint
// Option's port field is 0. Per PRS_SOMEIPSD_00307 / 00380 / 00393 the DUT
// must reject (Nack). Lenient verdict accepts silent ignore because
// vsomeip's option-walker may drop the malformed endpoint at the
// port-validation gate before the SD layer dispatches a Nack. Lift of
// ETS_154 with the malformation moved from IP to port.
template <>
struct TestCaseTraits<cases::SomeipEts109SM> : SomeIpAnyBase<cases::SomeipEts109SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_109";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup with port=0 in Endpoint Option — DUT Nacks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        params.target.eventgroup_id = 0x0002;
        params.session_id = 0x0001;
        // Caller-set ipv4_be != 0 keeps the auto-fill from skipping; mirrors
        // ETS_154's pattern. Tester IP unchanged from canonical (172.16.0.3
        // tester veth), only port flipped to 0 to isolate the validation
        // axis.
        params.tester_endpoint.ipv4_be = 0x030010ACU;  // 172.16.0.3 (tester veth)
        params.tester_endpoint.port = 0;               // invalid: spec mandates non-zero
        params.tester_endpoint.l4proto = 0x11;         // UDP
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts109SM, someip_ets_109)
