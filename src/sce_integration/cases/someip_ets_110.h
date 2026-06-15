#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_110_sm.h"

namespace tc8::sce::cases {

using SomeipEts110SM = ::SCE::Generated::someip_ets_110::someip_ets_110;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_110 — SubscribeEventgroup whose IPv4 Endpoint
// Option carries an invalid IPv4 (32.0.0.0 per spec — not a valid unicast
// address). Per PRS_SOMEIPSD_00306 / 00307 / 00380 / 00393 the DUT must
// reject (Nack). Lenient verdict accepts silent ignore because vsomeip's
// option-walker drops the IP at the validation gate. Lift of ETS_154 with
// the IP swapped to 32.0.0.0.
template <>
struct TestCaseTraits<cases::SomeipEts110SM> : SomeIpAnyBase<cases::SomeipEts110SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_110";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup with invalid IPv4 (32.0.0.0) — DUT Nacks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        params.target.eventgroup_id = 0x0002;
        params.session_id = 0x0001;
        // 32.0.0.0 = 0x20 0x00 0x00 0x00 wire bytes; ipv4_be on LE is
        // 0x00000020. Spec quote: "the transmitted IP is 32.0.0.0".
        params.tester_endpoint.ipv4_be = 0x00000020U;
        params.tester_endpoint.port = 30490U;
        params.tester_endpoint.l4proto = 0x11;  // UDP
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts110SM, someip_ets_110)
