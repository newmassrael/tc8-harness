#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_162_sm.h"

namespace tc8::sce::cases {

using SomeipEts162SM = ::SCE::Generated::someip_ets_162::someip_ets_162;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_162 — SubscribeEventgroup whose IPv4 Endpoint
// Option carries the DUT's own IP address (172.16.0.2). Per spec the DUT
// must reject (Nack); per PRS_SOMEIPSD_00306 / 00307 / 00380 / 00393 / 00566
// the option-walker / subnet-check rejects this as an "unallowed" endpoint
// (the subscriber must not advertise the publisher's address). Lenient
// verdict additionally accepts silent ignore because vsomeip's
// `sdi::process_eventgroupentry` may drop the malformed endpoint before its
// SD layer dispatches a Nack ("Subscriber's IP isn't in the same subnet"
// gate). Lift of ETS_154 with the IP swapped from limited-broadcast to
// DUT-self.
template <>
struct TestCaseTraits<cases::SomeipEts162SM> : SomeIpAnyBase<cases::SomeipEts162SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_162";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup with unallowed Endpoint IPv4 (DUT self) — DUT Nacks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        // Configured eg 0x0002 keeps the option walker past the unknown-eg
        // gate so the IPv4 endpoint axis is actually exercised. Subscribing
        // to an unknown eg would silent-drop at sdi::process_eventgroupentry
        // before the option walker sees the malformed endpoint.
        params.target.eventgroup_id = 0x0002;
        params.session_id = 0x0001;
        // 172.16.0.2 = DUT's own IP. Wire bytes AC 10 00 02 → ipv4_be on LE
        // Linux is 0x020010AC (matches SubscribeDestination::ipv4_be default).
        // Caller-set ipv4_be != 0 bypasses emitter's auto-fill so port +
        // l4proto must be set explicitly.
        params.tester_endpoint.ipv4_be = 0x020010ACU;
        params.tester_endpoint.port = tc8::dut::kSdPort;
        params.tester_endpoint.l4proto = 0x11;  // UDP
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts162SM, someip_ets_162)
