#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_151_sm.h"

namespace tc8::sce::cases {

using SomeipEts151SM = ::SCE::Generated::someip_ets_151::someip_ets_151;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_151 — SD_Send_triggerEventUINT8Reliable_Eventgroup_2.
//
// LENIENT — NOT YET FAITHFUL (tracked debt). The faithful case would trigger
// triggerEventUINT8Reliable (Method 0x05) and observe TestEventUINT8Reliable
// (Event 0x8003) delivered over TCP. That requires the tester to issue a Subscribe
// carrying BOTH a UDP and a valid TCP endpoint option (mixed-reliability eg) and
// to listen on TCP for the delivery — the dual-endpoint Subscribe the SD builder
// does not yet have. Until then, 0x8003 is isolated in eg 0x0007 (see ets.fdepl)
// and this case stays lenient: it subscribes eg 0x02 and accepts the always-on
// cyclic TestEventUINT8 (0x8001) per the §5.1.5.5 BASIC_03 pattern, verifying only
// the SD Ack — NOT the reliable event. Sibling 148/149/150 ARE faithful; 151 is
// the one still gated on dual-endpoint Subscribe. Do not count this as reliable-
// event coverage.
template <>
struct TestCaseTraits<cases::SomeipEts151SM> : SomeIpAnyBase<cases::SomeipEts151SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_151";
    static constexpr std::string_view kDescription =
        "Subscribe eg 0x02 — DUT Ack + cyclic notification (LENIENT; reliable "
        "0x8003 pending dual-endpoint Subscribe)";

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

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts151SM, someip_ets_151)
