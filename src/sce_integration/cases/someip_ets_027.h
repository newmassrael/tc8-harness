#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_027_sm.h"

namespace tc8::sce::cases {

using SomeipEts027SM = ::SCE::Generated::someip_ets_027::someip_ets_027;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_027 — echoUINT8 round-trip over UDP.
// The DUT shall return the same UInt8 value the tester sent. Wire shape:
// Method Request (msg_type 0x00, method_id 0x0008, payload [0x42]) →
// Method Response (msg_type 0x80, method_id 0x0008, return_code 0x00,
// payload [0x42]). Single-byte echo verification distinguishes this
// from §5.1.5.5 BASIC_01 which checks only the SOME/IP header.
template <>
struct TestCaseTraits<cases::SomeipEts027SM> : SomeIpAnyBase<cases::SomeipEts027SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_027";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "echoUINT8 round-trip — DUT echoes the UInt8 value sent in Method Request";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0008;
        target.payload = {0x42};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }

    // Conformant echo: case-local SSOT for the positive assertion;
    // --expect payload= overrides only for the negative harness.
    static void applyExpectedDefaults(::tc8::SomeIpExpected& e) {
        ::tc8::setExpectedPayload(e, {0x42});
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts027SM, someip_ets_027)
