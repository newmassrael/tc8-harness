#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_075_sm.h"

namespace tc8::sce::cases {

using SomeipEts075SM = ::SCE::Generated::someip_ets_075::someip_ets_075;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_075 — Wrong_Message_Type.
// Tester sends echoUINT8 (METHOD-ID 0x0008) with message_type
// header byte corrupted from 0x00 (Request) to 0x07 (reserved
// value — defined types are 0x00 Request / 0x01 RequestNoReturn
// / 0x02 Notification / 0x40 / 0x80 / 0x81 per SOME/IP §4.7.4).
// ETS_001-style lenient 4-path verdict.
template <>
struct TestCaseTraits<cases::SomeipEts075SM> : SomeIpAnyBase<cases::SomeipEts075SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_075";
    static constexpr std::string_view kDescription =
        "Wrong Message Type on echoUINT8 — DUT must reject or ignore";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0008;
        target.payload = {0x42};
        target.message_type = 0x07;  // Reserved per SOME/IP §4.7.4
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts075SM, someip_ets_075)
