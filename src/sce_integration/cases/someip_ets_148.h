#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/someip_method_dest.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_148_sm.h"

namespace tc8::sce::cases {

using SomeipEts148SM = ::SCE::Generated::someip_ets_148::someip_ets_148;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_148 — SD_Send_triggerEventUINT8Array_Eventgroup_2.
// Tester subscribes to eg 0x02, then calls triggerEventUINT8Array (Method 0x04,
// Fire&Forget) with start/duration/debounceTime; the DUT must Ack the Subscribe
// and emit TestEventUINT8Array (Event 0x8002) to the IP+port advertised in the
// Subscribe option. The SD machinery (OfferService -> SubscribeEventgroupAck ->
// Notification) follows the §5.1.5.5 BASIC_03 wire invariant; what makes this
// case spec-faithful (the trigger Method is now declared in ets.fdepl and the
// event is trigger-driven) is that phase 3 observes the specific Event 0x8002
// rather than the prior lenient "any MSB-set" match — the always-on cyclic
// TestEventUINT8 (0x8001) on eg 0x02 no longer satisfies it.
template <>
struct TestCaseTraits<cases::SomeipEts148SM> : SomeIpAnyBase<cases::SomeipEts148SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_148";
    static constexpr std::string_view kDescription =
        "Subscribe eg 0x02 + triggerEventUINT8Array — DUT Ack + Event 0x8002";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::SubscribeEventgroupTarget subscribe{};
        subscribe.eventgroup_id = 0x0002;
        ::tc8::stimulus::emitSubscribeEventgroupBoot(iface, subscribe, cfg.stimulus_timing);
        // triggerEventUINT8Array(start=0 s, duration=3 s, debounceTime=200 ms):
        // 3x UInt32 big-endian (SOME/IP network byte order). Fire&Forget
        // (message_type 0x01). Lands ~500 ms after the Subscribe Ack, so the
        // DUT's subscription endpoint is already recorded when it fires 0x8002.
        ::tc8::stimulus::MethodRequestTarget trigger{};
        trigger.method_id = 0x04;
        trigger.message_type = 0x01;
        trigger.payload = {0x00, 0x00, 0x00, 0x00,   // start = 0 s
                           0x00, 0x00, 0x00, 0x03,   // duration = 3 s
                           0x00, 0x00, 0x00, 0xC8};  // debounceTime = 200 ms
        ::tc8::stimulus::emitMethodRequestAfter(iface, trigger, {},
                                                ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts148SM, someip_ets_148)
