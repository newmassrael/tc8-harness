#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_onwire_02_sm.h"

namespace tc8::sce::cases {

using Onwire02SM = ::SCE::Generated::someipsrv_onwire_02::someipsrv_onwire_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.6.2 — Method ID 16-bit field, MSB=0 for Method/Response
// (MSB=1 reserved for Notification/Event IDs). Tester invokes echoUINT8
// (METHOD-ID-1-SI-1 = 0x0008); pass requires the Response carries
// (method_id & 0x8000) == 0.
template <>
struct TestCaseTraits<cases::Onwire02SM> : SomeIpAnyBase<cases::Onwire02SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_ONWIRE_02";
    static constexpr std::string_view kDescription =
        "Method ID MSB cleared in Method Response";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.payload = {0x42};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Onwire02SM, someipsrv_onwire_02)
