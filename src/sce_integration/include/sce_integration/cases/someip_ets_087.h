#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_087_sm.h"

namespace tc8::sce::cases {

using SomeipEts087SM = ::SCE::Generated::someip_ets_087::someip_ets_087;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_087 — Eventgroup_EventsAndFieldsUnreliable_5.
// Tester subscribes to eventgroup 0x05 on SERVICE-ID-1; DUT must Ack
// the Subscribe and send each initial event the procedure lists for
// eg 0x05: 0x8005, 0x8006 and 0x8007, all over UDP (the "Unreliable" of
// the case name; eg 0x05 carries no reliable field). The SCXML waits for
// all three in any order, as ETS_086 does for eg 0x02.
template <>
struct TestCaseTraits<cases::SomeipEts087SM> : SomeIpAnyBase<cases::SomeipEts087SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_087";
    static constexpr std::string_view kDescription =
        "Subscribe to eventgroup 0x05 — DUT Ack + initial events 0x8005..0x8007";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        ::tc8::stimulus::emitFindServiceBoot(ctx.iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::SubscribeEventgroupTarget subscribe{};
        subscribe.eventgroup_id = 0x0005;
        ::tc8::stimulus::emitSubscribeEventgroupBoot(ctx.iface, subscribe, cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts087SM, someip_ets_087)
