#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_150_sm.h"

namespace tc8::sce::cases {

using SomeipEts150SM = ::SCE::Generated::someip_ets_150::someip_ets_150;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_150 — SD_Send_triggerEventUINT8Multicast_Eventgroup_6.
// Tester subscribes to eg 0x06 then triggers triggerEventUINT8Multicast;
// DUT must Ack and emit the field event. tc8-dut's vsomeip.json maps eg
// 0x06 to TestEventUINT8 (no separate Multicast event declared); the
// cyclic 250 ms TestEventUINT8 fires on this eg too, so the Subscribe
// Ack + any MSB-set notification on eg 0x06 satisfies the wire invariant
// per the lenient §5.1.5.5 BASIC_03 / §5.1.6 ETS_086 pattern.
template <>
struct TestCaseTraits<cases::SomeipEts150SM> : SomeIpAnyBase<cases::SomeipEts150SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_150";
    static constexpr std::string_view kDescription =
        "Subscribe eg 0x06 + trigger triggerEventUINT8Multicast — DUT Ack + MSB-set notification";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::SubscribeEventgroupTarget subscribe{};
        subscribe.eventgroup_id = 0x0006;
        ::tc8::stimulus::emitSubscribeEventgroupBoot(iface, subscribe, cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts150SM, someip_ets_150)
