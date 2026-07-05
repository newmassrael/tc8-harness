#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/someip_method_dest.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"
#include "stimulus/subscribe_tcp_session.h"

#include "someip_ets_094_sm.h"

namespace tc8::sce::cases {

using SomeipEts094SM = ::SCE::Generated::someip_ets_094::someip_ets_094;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_094 — SD_Check_Reboot_Detection_Server_Side.
// Tester subscribes to eventgroup 0x02 on SERVICE-ID-1; DUT must Ack the
// Subscribe and start emitting cyclic TestEventUINT8. The tester then
// emits two FindService datagrams whose SD Session-IDs are equal
// (0x0005 and 0x0005) with the reboot flag set in both. vsomeip's
// `service_discovery_impl::is_reboot` rule (old_rb=1 && new_rb=1 &&
// old_sid >= new_sid) treats the second FindService as a reboot of the
// tester and runs `expire_subscriptions(_sender)`, after which the DUT
// must stop sending TestEventUINT8 (PRS_SOMEIPSD_00157).
//
// The `TriggerEventUint8` method called out in the spec body is not
// required by tc8-dut: dut_main fires `TestEventUINT8` on a 250 ms
// cyclic broadcast (vsomeip distributes only to currently subscribed
// clients), so the post-Subscribe / post-first-FindService positive
// observations are satisfied by that broadcast. The lenient
// substitution mirrors §5.1.6 ETS_086/_087's "MSB-set Notification"
// shape: the tester observes the cyclic event once it is subscribed,
// which is the wire signal the spec equates with TriggerEvent.
//
// The two scheduled FindService emits ride on
// `IStimulusScheduler::scheduleAfterStateEntry` so timing tracks the
// SCXML's phase advance instead of wall clock — robust under
// workers=4 capture jitter.
template <>
struct TestCaseTraits<cases::SomeipEts094SM> : SomeIpAnyBase<cases::SomeipEts094SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_094";
    static constexpr std::string_view kDescription =
        "Server-side reboot detection — duplicate SD session_id triggers expire_subscriptions";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler,
                         ::tc8::sce::IBackgroundServiceOwner& owner) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        // eg 0x0002 is mixed-reliability: hold a TCP connection so vsomeip Acks
        // the dual-endpoint Subscribe. The reboot FindServices below still
        // expire the subscription (the DUT stops the UNRELIABLE 0x8001 over UDP).
        auto session = std::make_unique<::tc8::stimulus::SubscribeEventgroupTcpSession>(
            iface, ::tc8::sce::someipTcpMethodDest(cfg));
        ::tc8::stimulus::SubscribeEventgroupTarget subscribe{};
        subscribe.eventgroup_id = 0x0002;
        subscribe.ttl = 16;
        ::tc8::stimulus::SubscribeDestination sd_dest{};
        sd_dest.ipv4_be = cfg.someip.dut_iface_ip;
        session->subscribeDual(subscribe, sd_dest);
        owner.adoptService(std::move(session));

        // Capture-by-value so the lambdas survive past kickStimulus return.
        std::string iface_copy(iface);

        // First FindService — Session-ID 0x05, reboot flag set. Old
        // multicast tracker is (rb=1, sid=2) from emitFindServiceBoot's
        // last emit, so 2 < 5 satisfies the strict-increment guard and
        // vsomeip does NOT detect a reboot here. DUT continues serving.
        // The 500 ms `Listening_phase4_settle` gate (see SCXML) gives
        // the runner one tick with phase4_settle as the current state
        // so this observer matches before fast-back-to-back cyclic
        // events skip the state between two pcap_dispatch drains.
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_phase4_settle),
            [iface_copy]() {
                ::tc8::stimulus::FindServiceParams p{};
                p.session_id = 0x0005;
                p.sd_flags   = 0xC0;
                auto datagram = ::tc8::stimulus::buildFindService(p);
                ::tc8::stimulus::sendSdMulticast(datagram, iface_copy);
            });

        // Second FindService — same Session-ID 0x05, reboot flag still
        // set. Old multicast tracker is now (rb=1, sid=5); the
        // is_reboot rule fires (5 >= 5) → vsomeip runs
        // `expire_subscriptions(_sender)` and DUT stops sending
        // TestEventUINT8 to the tester.
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_phase5_drain),
            [iface_copy]() {
                ::tc8::stimulus::FindServiceParams p{};
                p.session_id = 0x0005;
                p.sd_flags   = 0xC0;
                auto datagram = ::tc8::stimulus::buildFindService(p);
                ::tc8::stimulus::sendSdMulticast(datagram, iface_copy);
            });
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts094SM, someip_ets_094)
