#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/someip_method_dest.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_150_sm.h"

namespace tc8::sce::cases {

using SomeipEts150SM = ::SCE::Generated::someip_ets_150::someip_ets_150;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_150 — SD_Send_triggerEventUINT8Multicast_Eventgroup_6.
// Tester subscribes to eg 0x06, then calls triggerEventUINT8Multicast (Method
// 0x3A, Fire&Forget). The DUT must Ack and emit TestEventUINT8Multicast (Event
// 0x800B). The SD machinery follows the §5.1.5.5 BASIC_03 wire invariant; what
// makes this case spec-faithful is that phase 3 observes the specific Event
// 0x800B — the cyclic TestEventUINT8 (0x8001) on the same eg no longer satisfies
// it. (eg 0x06 has no multicast endpoint in vsomeip.json, so 0x800B is delivered
// unicast to the subscribed endpoint; observing the Event ID is the faithful
// axis, transport-independent.)
template <>
struct TestCaseTraits<cases::SomeipEts150SM> : SomeIpAnyBase<cases::SomeipEts150SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_150";
    static constexpr std::string_view kDescription =
        "Subscribe eg 0x06 + triggerEventUINT8Multicast — DUT Ack + Event 0x800B";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::SubscribeEventgroupTarget subscribe{};
        subscribe.eventgroup_id = 0x0006;
        ::tc8::stimulus::emitSubscribeEventgroupBoot(iface, subscribe, cfg.stimulus_timing);
        // triggerEventUINT8Multicast(start=0 s, duration=3 s, debounceTime=200 ms):
        // 3x UInt32 big-endian, Fire&Forget (message_type 0x01).
        ::tc8::stimulus::MethodRequestTarget trigger{};
        trigger.method_id = 0x3A;
        trigger.message_type = 0x01;
        trigger.payload = {0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x03,
                           0x00, 0x00, 0x00, 0xC8};
        ::tc8::stimulus::emitMethodRequestAfter(iface, trigger, {},
                                                ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts150SM, someip_ets_150)
