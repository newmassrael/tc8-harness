#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_117_sm.h"

namespace tc8::sce::cases {

using SomeipEts117SM = ::SCE::Generated::someip_ets_117::someip_ets_117;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_117 — SubscribeEventgroup with two options of
// the same IPv4 Endpoint type. Per PRS_SOMEIPSD_00393 the DUT MUST Nack OR
// silently ignore. Wire shape: canonical first option + a second IPv4
// Endpoint option of the same kind, BOTH referenced by the entry
// (`#Opt1=2`). Verdict is strict: Nack (Type 0x07 ttl==0) OR silent ignore
// → pass; Ack (Type 0x07 ttl>0) → fail. vsomeip rejects the pair in
// `sdi::process_eventgroupentry` ("Multiple IPv4 endpoint options of same
// kind referenced", SIP_SD_1144) and Nacks, so the reference DUT passes.
// The earlier wire shape left the second option UNREFERENCED (`#Opt1=1`),
// which vsomeip accepted with an Ack — that is why this case was once
// platform_known_fail. ETS_173 phase 2 exercises the mixed-transport
// variant of the same option-reference rule.
template <>
struct TestCaseTraits<cases::SomeipEts117SM> : SomeIpAnyBase<cases::SomeipEts117SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_117";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup with two same-type (IPv4 Endpoint) options — DUT Nacks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        // Two IPv4 Endpoint options of the SAME kind (both UDP), both canonical
        // (appendIpv4EndpointOption via tester_endpoint + second_endpoint — no
        // hand-encoded option bytes). Target the UNRELIABLE eg 0x0005 so the sole
        // malformation the DUT evaluates is the duplicate-kind option references
        // (vsomeip's process_eventgroupentry rejects them); on the mixed eg 0x0002
        // the reliability check would preempt this. #Opt1=2 references both.
        ::tc8::stimulus::SubscribeEventgroupParams params{};
        params.target.eventgroup_id = 0x0005;
        params.session_id = 0x0001;
        params.second_endpoint =
            ::tc8::stimulus::Ipv4Endpoint{cfg.ipv4.tester_ip, tc8::dut::kSdPort, 0x11};
        params.num_options_first_override = std::uint8_t{2};
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts117SM, someip_ets_117)
