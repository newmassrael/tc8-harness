#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_119_sm.h"

namespace tc8::sce::cases {

using SomeipEts119SM = ::SCE::Generated::someip_ets_119::someip_ets_119;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_119 — SubscribeEventgroup with IPv4 Endpoint
// option l4proto != UDP (0x11) and != TCP (0x06). Per PRS_SOMEIPSD_00307 /
// 00393 the DUT must Nack. Lenient verdict accepts silent ignore at
// vsomeip's L4-validation gate. Lift of ETS_154 with the malformation
// moved from IP to l4proto (here: 0x42 — neither UDP nor TCP).
template <>
struct TestCaseTraits<cases::SomeipEts119SM> : SomeIpAnyBase<cases::SomeipEts119SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_119";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup with wrong l4proto (neither UDP nor TCP) — DUT Nacks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        params.target.eventgroup_id = 0x0002;
        params.session_id = 0x0001;
        // Tester IP unchanged from canonical (172.16.0.3 tester veth);
        // only l4proto flipped to 0x42 (arbitrary non-UDP non-TCP value).
        params.tester_endpoint.ipv4_be = 0x030010ACU;  // 172.16.0.3
        params.tester_endpoint.port = 30490U;
        params.tester_endpoint.l4proto = 0x42;  // neither 0x11 (UDP) nor 0x06 (TCP)
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts119SM, someip_ets_119)
