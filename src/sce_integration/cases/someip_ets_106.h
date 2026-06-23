#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_106_sm.h"

namespace tc8::sce::cases {

using SomeipEts106SM = ::SCE::Generated::someip_ets_106::someip_ets_106;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_106 — DUT in Client Mode subscribes to the
// Tester's ETS service. Stimulus chain:
//   1. clientServiceActivate (Method 0x2F Fire&Forget) — DUT enters
//      Proxy mode; CommonAPI proxy spawn starts emitting FindService
//      for SERVICE-ID-2 (ets3 ClientTarget).
//   2. clientServiceSubscribeEventgroup (Method 0x32 Fire&Forget) —
//      DUT-side Proxy wires up Subscribe behavior on the target
//      eventgroup (`client_mode_proxy.subscribe()`).
//   3. emitOfferServiceMulticastWithEndpoint (SERVICE-ID-2 + tester TCP
//      endpoint) — tester pretends to offer the ets3 service.
//   4. DUT's Proxy (now woken up by the Offer it expected) emits a
//      SubscribeEventgroup back to tester. Phase 2 observes that
//      Subscribe.
// Per PRS_SOMEIPSD_00386 / 00387 / 00391 the DUT must emit a Subscribe
// targeting the offered SERVICE-ID-2 once both the activate trigger and
// the matching offer arrive. CASE_VSOMEIP_VARIANT="client-mode" gates
// TC8_DUT_CLIENT_MODE=1 in `smoke-test.sh`.
template <>
struct TestCaseTraits<cases::SomeipEts106SM> : SomeIpAnyBase<cases::SomeipEts106SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_106";
    static constexpr std::string_view kDescription =
        "Client-Mode + clientServiceSubscribeEventgroup + Offer — DUT emits Subscribe";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        // 1. clientServiceActivate (Method 0x2F Fire&Forget) — payload
        // delay byte = 0 means "no extra defer beyond the Proxy spawn".
        ::tc8::stimulus::MethodRequestTarget activate{};
        activate.method_id    = 0x002F;
        activate.message_type = 0x01;  // RequestNoReturn (Fire&Forget).
        activate.payload      = {0x00};
        ::tc8::stimulus::emitMethodRequestAfter(iface, activate);
        std::this_thread::sleep_for(std::chrono::milliseconds(800));

        // 2. clientServiceSubscribeEventgroup (Method 0x32 Fire&Forget) —
        // 4-byte delay + 4-byte duration both zero.
        ::tc8::stimulus::MethodRequestTarget subscribe{};
        subscribe.method_id    = 0x0032;
        subscribe.message_type = 0x01;
        subscribe.payload      = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        ::tc8::stimulus::emitMethodRequestAfter(iface, subscribe);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // 3. emitOfferServiceMulticastWithEndpoint — advertise tester's
        // UDP unreliable endpoint for ets3 SERVICE-ID 0xF4E9. UDP variant
        // (CASE_VSOMEIP_VARIANT="client-mode-udp" → TC8_DUT_CLIENT_MODE_UDP=1)
        // makes the DUT proxy subscribe via UDP eg 0x000B, so no TCP listener
        // pre-establish is needed (vs ETS_097's TCP-reliable path). vsomeip
        // emits a SubscribeEventgroup carrying a UDP IPv4 Endpoint Option.
        ::tc8::stimulus::OfferServiceWithEndpointTarget offer{};
        offer.service.service_id    = 0xF4E9;     // ets3 SERVICE-ID
        offer.service.instance_id   = 0x0001;
        offer.service.major_version = 0x01;
        offer.service.ttl           = 5;
        offer.service.session_id    = 0x0001;
        offer.endpoint.port         = 30510U;     // ets3 UDP unreliable port
        offer.endpoint.l4proto      = 0x11;       // UDP
        ::tc8::stimulus::emitOfferServiceMulticastWithEndpoint(
            iface, offer, std::chrono::milliseconds(500));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts106SM, someip_ets_106)
