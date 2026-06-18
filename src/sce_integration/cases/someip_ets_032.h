#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_032_sm.h"

namespace tc8::sce::cases {

using SomeipEts032SM = ::SCE::Generated::someip_ets_032::someip_ets_032;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_032 — echoUINT8ArrayMinSize happy-path.
// Tester sends a 4-element array (within the spec-defined 3..5 range)
// with 32-bit BE length prefix to METHOD-ID 0x0037. DUT echoes the
// array back. ETS_033 sends a too-short array on the same method ID.
template <>
struct TestCaseTraits<cases::SomeipEts032SM> : SomeIpAnyBase<cases::SomeipEts032SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_032";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "echoUINT8ArrayMinSize round-trip — 4-element array within 3..5 range";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0037;
        // CommonAPI UInt8[] with 32-bit BE length prefix:
        // [len_BE = 0x00000004] [0x10 0x11 0x12 0x13]. payload_len = 8.
        target.payload = {0x00, 0x00, 0x00, 0x04, 0x10, 0x11, 0x12, 0x13};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }

    // Conformant echo: case-local SSOT for the positive assertion;
    // --expect payload= overrides only for the negative harness.
    static void applyExpectedDefaults(::tc8::SomeIpExpected& e) {
        ::tc8::setExpectedPayload(e, {0x00, 0x00, 0x00, 0x04, 0x10, 0x11, 0x12, 0x13});
    }
};

// Compile-time guard: the SFINAE detector must see this case's
// applyExpectedDefaults hook. A name/type drift would silently skip the
// case-local default at runtime and false-FAIL a conformant positive run.
static_assert(has_expected_defaults_v<TestCaseTraits<cases::SomeipEts032SM>>,
              "SOMEIP_ETS_032: applyExpectedDefaults must be detected");

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts032SM, someip_ets_032)
