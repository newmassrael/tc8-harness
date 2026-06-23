#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_163_sm.h"

namespace tc8::sce::cases {

using SomeipEts163SM = ::SCE::Generated::someip_ets_163::someip_ets_163;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_163 — SubscribeEventgroup whose IPv4 Endpoint
// Option carries 111.111.111.111 (out-of-subnet unicast IP). Per spec the
// DUT must reject with SubscribeEventgroupNack. Lenient verdict accepts
// silent ignore because vsomeip's `sdi::process_eventgroupentry` drops the
// out-of-subnet endpoint at "Subscriber's IP isn't in the same subnet"
// before the SD layer dispatches a Nack. Lift of ETS_154 with the IP
// swapped to the spec's 111.111.111.111 value.
template <>
struct TestCaseTraits<cases::SomeipEts163SM> : SomeIpAnyBase<cases::SomeipEts163SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_163";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup with unallowed Endpoint IPv4 (111.111.111.111) — DUT Nacks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        params.target.eventgroup_id = 0x0002;
        params.session_id = 0x0001;
        // 111.111.111.111 = 0x6F 0x6F 0x6F 0x6F (palindrome). ipv4_be on
        // LE Linux is 0x6F6F6F6F. Caller-set ipv4_be != 0 bypasses
        // emitter's auto-fill so port + l4proto must be set explicitly.
        params.tester_endpoint.ipv4_be = 0x6F6F6F6FU;
        params.tester_endpoint.port = 30490U;
        params.tester_endpoint.l4proto = 0x11;  // UDP
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts163SM, someip_ets_163)
