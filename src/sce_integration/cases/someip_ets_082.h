#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_082_sm.h"

namespace tc8::sce::cases {

using SomeipEts082SM = ::SCE::Generated::someip_ets_082::someip_ets_082;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_082 — ClientServiceActivate_Server_reboot_2.
// UDP companion to ETS_081: after the DUT proxy subscribes via UDP
// (eventgroup 0x000B in ets3.fdepl, gated by TC8_DUT_CLIENT_MODE_UDP=1),
// the tester emits OfferService #1 with a UDP endpoint, then OfferService
// #2 with a LOWER session_id and a different tester UDP port. vsomeip's
// `is_reboot` rule (old_rb=1 && new_rb=1 && old_sid >= new_sid) triggers
// expire_subscriptions, and the DUT must emit a second SubscribeEventgroup
// against the new tester endpoint per PRS_SOMEIPSD_00385.
//
// Verdict relies purely on observing TWO wire SubscribeEventgroup frames
// with l4_proto = UDP — UDP is connectionless so there's no TCP-handshake
// signal to count.
template <>
struct TestCaseTraits<cases::SomeipEts082SM> : SomeIpAnyBase<cases::SomeipEts082SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_082";
    static constexpr std::string_view kDescription =
        "Server-reboot recovery via UDP — DUT re-subscribes with new tester UDP port";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);

        ::tc8::stimulus::MethodRequestTarget activate{};
        activate.method_id    = 0x002F;       // clientServiceActivate
        activate.message_type = 0x01;         // Fire&Forget
        activate.payload      = {0x00};       // delay = 0
        ::tc8::stimulus::emitMethodRequestAfter(iface, activate);

        // Proxy buildProxy() registration delay — same gap as ETS_081/_084/_097.
        std::this_thread::sleep_for(std::chrono::milliseconds(800));

        ::tc8::stimulus::MethodRequestTarget sub_trigger{};
        sub_trigger.method_id    = 0x0032;    // clientServiceSubscribeEventgroup
        sub_trigger.message_type = 0x01;      // Fire&Forget
        sub_trigger.payload      = {0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00};
        ::tc8::stimulus::emitMethodRequestAfter(iface, sub_trigger);

        // Tester-side OfferService #1 for ets3 with UDP endpoint at
        // port 30510. session_id = 0x000A high enough that the
        // emitFindServiceBoot tail (rb=1, sid=2) does not trip is_reboot
        // here (2 < 10).
        ::tc8::stimulus::OfferServiceWithEndpointTarget offer1{};
        offer1.service.service_id    = 0xF4E9;   // ets3 SERVICE-ID
        offer1.service.instance_id   = 0x0001;
        offer1.service.major_version = 0x01;
        offer1.service.ttl           = 5;
        offer1.service.session_id    = 0x000A;
        offer1.endpoint.port         = 30510;
        offer1.endpoint.l4proto      = 0x11;     // UDP
        ::tc8::stimulus::emitOfferServiceMulticastWithEndpoint(
            iface, offer1, std::chrono::milliseconds(500));

        // Schedule the reboot OfferService on phase 3 entry — fired
        // immediately after the harness observes DUT's first wire
        // Subscribe (UDP option). vsomeip's is_reboot rule (old_sid=10
        // >= new_sid=5, both rb=1) triggers expire_subscriptions on the
        // sender → DUT re-subscribes with the new tester endpoint info
        // (port 30511) embedded by reference in offer #2.
        std::string iface_copy(iface);
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_phase3_second_subscribe),
            [iface_copy]() {
                ::tc8::stimulus::OfferServiceWithEndpointTarget offer2{};
                offer2.service.service_id    = 0xF4E9;
                offer2.service.instance_id   = 0x0001;
                offer2.service.major_version = 0x01;
                offer2.service.ttl           = 5;
                offer2.service.session_id    = 0x0005;  // < offer1.sid → reboot
                offer2.endpoint.port         = 30511;   // new tester UDP port
                offer2.endpoint.l4proto      = 0x11;
                ::tc8::stimulus::emitOfferServiceMulticastWithEndpoint(
                    iface_copy, offer2, std::chrono::milliseconds(0));
            });
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts082SM, someip_ets_082)
