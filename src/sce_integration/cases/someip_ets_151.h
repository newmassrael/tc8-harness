#pragma once

#include <memory>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/someip_method_dest.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"
#include "stimulus/subscribe_tcp_session.h"

#include "someip_ets_151_sm.h"

namespace tc8::sce::cases {

using SomeipEts151SM = ::SCE::Generated::someip_ets_151::someip_ets_151;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_151 — SD_Send_triggerEventUINT8Reliable_Eventgroup_2.
//
// FAITHFUL reliable-event case. Unlike the UDP siblings (147/148/149), the event
// here — TestEventUINT8Reliable (0x8003) — is delivered over TCP, so the tester
// must hold a live reliable connection for it to be observable. The stimulus:
//   1. FindService boot (DUT offers SERVICE-ID-1 with its reliable endpoint);
//   2. open a `SubscribeEventgroupTcpSession` — a client-initiated TCP connection
//      to the DUT reliable endpoint that it HOLDS open (adopted by the runner as
//      an IPollableService for the capture window) — and Subscribe eventgroup
//      0x0007 advertising that TCP endpoint (l4proto 0x06);
//   3. call triggerEventUINT8Reliable (Method 0x05, Fire&Forget).
// vsomeip pushes the reliable event back over the tcp_server_endpoint connection
// the subscriber opened. The SD machinery (OfferService -> SubscribeEventgroupAck
// -> Notification) follows the §5.1.5.5 BASIC_03 wire invariant; phase 3 observes
// the specific Event 0x8003 over TCP, not the always-on cyclic 0x8001 — the same
// tightening the faithful UDP siblings (148/149/150) make over their events.
//
// EVENTGROUP DEVIATION (residual debt): the spec places 0x8003 on eg 0x02 mixed
// with the unreliable events; the harness isolates it in reliable-only eg 0x0007
// (see ets.fdepl) so a Subscribe stays Ack-able without the dual UDP+TCP endpoint
// option the SD builder does not yet emit. The reliable event is now OBSERVED
// (0x8003 over TCP); the residual gap is only the eg-0x02 form of the Subscribe.
template <>
struct TestCaseTraits<cases::SomeipEts151SM> : SomeIpAnyBase<cases::SomeipEts151SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_151";
    static constexpr std::string_view kDescription =
        "Subscribe eg 0x07 over live TCP + triggerEventUINT8Reliable — DUT Ack + "
        "Event 0x8003 over TCP";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IBackgroundServiceOwner& owner) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        // Client-initiated reliable session: connect + hold the TCP connection to
        // the DUT reliable endpoint, Subscribe eg 0x0007 advertising it, then hand
        // ownership to the runner so the connection stays open across the capture
        // window (the DUT keeps delivering 0x8003 over it).
        auto session = std::make_unique<::tc8::stimulus::SubscribeEventgroupTcpSession>(
            iface, ::tc8::sce::someipTcpMethodDest(cfg));
        ::tc8::stimulus::SubscribeEventgroupTarget subscribe{};
        subscribe.eventgroup_id = 0x0007;  // reliable-only eg carrying 0x8003 (ets.fdepl).
        subscribe.ttl = 16;                // outlast the emission window below.
        ::tc8::stimulus::SubscribeDestination sd_dest{};
        sd_dest.ipv4_be = cfg.someip.dut_iface_ip;  // DUT SD endpoint (:30490).
        session->subscribe(subscribe, sd_dest);
        owner.adoptService(std::move(session));
        // triggerEventUINT8Reliable (Method 0x05, Fire&Forget): start=0 s,
        // duration=5 s, debounceTime=200 ms → DUT fires 0x8003 over the held TCP.
        ::tc8::stimulus::SomeIpRpcMessage trigger{};
        trigger.method_id = 0x05;
        trigger.message_type = ::tc8::someip::MessageType::REQUEST_NO_RETURN;
        trigger.payload = {0x00, 0x00, 0x00, 0x00,   // start = 0 s
                           0x00, 0x00, 0x00, 0x05,   // duration = 5 s
                           0x00, 0x00, 0x00, 0xC8};  // debounceTime = 200 ms
        ::tc8::stimulus::emitMethodRequestAfter(iface, trigger, {},
                                                ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts151SM, someip_ets_151)
