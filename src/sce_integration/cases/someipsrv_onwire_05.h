#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_onwire_05_sm.h"

namespace tc8::sce::cases {

using Onwire05SM = ::SCE::Generated::someipsrv_onwire_05::someipsrv_onwire_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.6.5 — Protocol Version 8-bit field shall be 0x01.
// Tester invokes echoUINT8 with the canonical PV; pass requires the
// matched Response carries protocol_version == 0x01.
template <>
struct TestCaseTraits<cases::Onwire05SM> : SomeIpAnyBase<cases::Onwire05SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_ONWIRE_05";
    static constexpr std::string_view kDescription =
        "Method Response carries Protocol Version 0x01";

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

TC8_REGISTER_CASE(::tc8::sce::cases::Onwire05SM, someipsrv_onwire_05)
