#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_149_sm.h"

namespace tc8::sce::cases {

using SomeipEts149SM = ::SCE::Generated::someip_ets_149::someip_ets_149;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_149 — SD_Send_triggerEventUINT8_Eventgroup_2.
// Tester subscribes to eg 0x02 then triggers triggerEventUINT8; DUT must
// Ack and emit TestEventUINT8 to the IP+port advertised in the Subscribe
// option. tc8-dut's cyclic 250 ms TestEventUINT8 fires regardless of an
// explicit trigger Method (which is not declared in ets.fdepl), so the
// Subscribe Ack + any MSB-set notification on eg 0x02 satisfies the wire
// invariant per the §5.1.5.5 BASIC_03 / §5.1.6 ETS_086 lenient pattern.
template <>
struct TestCaseTraits<cases::SomeipEts149SM> : SomeIpAnyBase<cases::SomeipEts149SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_149";
    static constexpr std::string_view kDescription =
        "Subscribe eg 0x02 + trigger triggerEventUINT8E2E — DUT Ack + MSB-set notification";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::SubscribeEventgroupTarget subscribe{};
        subscribe.eventgroup_id = 0x0002;
        ::tc8::stimulus::emitSubscribeEventgroupBoot(iface, subscribe, cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts149SM, someip_ets_149)
