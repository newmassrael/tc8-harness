#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_009_sm.h"

namespace tc8::sce::cases {

using SomeipEts009SM = ::SCE::Generated::someip_ets_009::someip_ets_009;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_009 — echoENUM round-trip. Tester sends a
// single 1-byte enum value (0x02 = VALUE_C) to METHOD-ID 0x0017; DUT
// echoes the same byte back. CommonAPI-SOMEIP enum width pinned to 1
// in ets.fdepl so the on-wire shape matches the spec table's Uint8
// ReqArg1 / ResArg1 (p401-420). 0x02 is preferred over 0x00/0x01 so a
// regression that drops the enum value to default-init can't trivially
// pass the cond.
template <>
struct TestCaseTraits<cases::SomeipEts009SM> : SomeIpAnyBase<cases::SomeipEts009SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_009";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "echoENUM round-trip — DUT echoes the 1-byte enum VALUE_C (0x02)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0017;
        // 1-byte enum payload (SomeIpEnumWidth=1, BitWidth=8).
        target.payload = {0x02};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }

    // Conformant echo: case-local SSOT for the positive assertion;
    // --expect payload= overrides only for the negative harness.
    static void applyExpectedDefaults(::tc8::SomeIpExpected& e) {
        ::tc8::setExpectedPayload(e, {0x02});
    }
};

// Compile-time guard: the SFINAE detector must see this case's
// applyExpectedDefaults hook. A name/type drift would silently skip the
// case-local default at runtime and false-FAIL a conformant positive run.
static_assert(has_expected_defaults_v<TestCaseTraits<cases::SomeipEts009SM>>,
              "SOMEIP_ETS_009: applyExpectedDefaults must be detected");

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts009SM, someip_ets_009)
