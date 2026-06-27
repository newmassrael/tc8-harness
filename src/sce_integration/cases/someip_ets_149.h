#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/someip_method_dest.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_149_sm.h"

namespace tc8::sce::cases {

using SomeipEts149SM = ::SCE::Generated::someip_ets_149::someip_ets_149;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_149 — SD_Send_triggerEventUINT8E2E_Eventgroup_2.
// Tester subscribes to eg 0x02, then calls triggerEventUINT8E2E (Method 0x06,
// Fire&Forget). The DUT must Ack and emit TestEventUINT8E2E (Event 0x8004) to
// the IP+port advertised in the Subscribe option. The SD machinery follows the
// §5.1.5.5 BASIC_03 wire invariant; what makes this case spec-faithful is that
// phase 3 observes the specific Event 0x8004 — the cyclic TestEventUINT8 (0x8001)
// on the same eg no longer satisfies it.
template <>
struct TestCaseTraits<cases::SomeipEts149SM> : SomeIpAnyBase<cases::SomeipEts149SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_149";
    static constexpr std::string_view kDescription =
        "Subscribe eg 0x02 + triggerEventUINT8E2E — DUT Ack + Event 0x8004";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::SubscribeEventgroupTarget subscribe{};
        subscribe.eventgroup_id = 0x0002;
        ::tc8::stimulus::emitSubscribeEventgroupBoot(iface, subscribe, cfg.stimulus_timing);
        // triggerEventUINT8E2E(start=0 s, duration=3 s, debounceTime=200 ms):
        // 3x UInt32 big-endian, Fire&Forget (message_type 0x01).
        ::tc8::stimulus::MethodRequestTarget trigger{};
        trigger.method_id = 0x06;
        trigger.message_type = 0x01;
        trigger.payload = {0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x03,
                           0x00, 0x00, 0x00, 0xC8};
        ::tc8::stimulus::emitMethodRequestAfter(iface, trigger, {},
                                                ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts149SM, someip_ets_149)
