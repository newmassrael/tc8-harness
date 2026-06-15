#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_078_sm.h"

namespace tc8::sce::cases {

using SomeipEts078SM = ::SCE::Generated::someip_ets_078::someip_ets_078;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_078 — Wrong_SOMEIP_Protocol_Version.
// Tester sends echoUINT8 (METHOD-ID 0x0008) with protocol_version
// header byte corrupted from 0x01 (SOME/IP V1.1) to 0xFF. ETS_001-
// style lenient 4-path verdict.
template <>
struct TestCaseTraits<cases::SomeipEts078SM> : SomeIpAnyBase<cases::SomeipEts078SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_078";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "Wrong SOME/IP Protocol Version on echoUINT8 — DUT must reject or ignore";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0008;
        target.payload = {0x42};
        target.protocol_version = 0xFF;  // SOME/IP V1.1 fixed at 0x01
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts078SM, someip_ets_078)
