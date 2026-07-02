#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_154_sm.h"

namespace tc8::sce::cases {

using SomeipEts154SM = ::SCE::Generated::someip_ets_154::someip_ets_154;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_154 — SubscribeEventgroup whose IPv4
// Endpoint Option carries 255.255.255.255 (limited broadcast — illegal
// as a unicast Subscribe endpoint per RFC 919). Per PRS_SOMEIPSD_00306
// / 00307 / 00380 / 00393 the DUT must Nack. Lenient verdict additionally
// accepts silent ignore because vsomeip's option-walker may drop the
// ambiguous endpoint before its SD layer dispatches a Nack.
template <>
struct TestCaseTraits<cases::SomeipEts154SM> : SomeIpAnyBase<cases::SomeipEts154SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_154";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup with invalid IPv4 endpoint (255.255.255.255) — DUT Nacks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        // Use a configured eg (0x0002 — TestEventUINT8) so the DUT walks
        // past the unknown-eventgroup gate and actually exercises the
        // IPv4 endpoint validation axis. Subscribing to 0x0001 would
        // silent-drop at sdi::process_eventgroupentry before the option
        // walker sees the malformed endpoint.
        params.target.eventgroup_id = 0x0002;
        params.session_id = 0x0001;
        // 255.255.255.255 — limited broadcast IP, invalid as a unicast
        // Subscribe endpoint. Caller-set ipv4_be != 0 bypasses the
        // emitter's auto-fill so port + l4proto must be set explicitly
        // to canonical SD UDP values; the only invalid bit is the IP.
        params.tester_endpoint.ipv4_be = 0xFFFFFFFFU;
        params.tester_endpoint.port = tc8::dut::kSdPort;
        params.tester_endpoint.l4proto = 0x11;  // UDP
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts154SM, someip_ets_154)
