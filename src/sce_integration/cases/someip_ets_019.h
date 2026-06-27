#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_019_sm.h"

namespace tc8::sce::cases {

using SomeipEts019SM = ::SCE::Generated::someip_ets_019::someip_ets_019;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_019 — echoFLOAT64 round-trip. Tester sends
// a single Double value (1.5 = 0x3FF8000000000000 BE) to METHOD-ID
// 0x0012; DUT echoes the same 8-byte value back. The pass cond pins
// every byte of the BE encoding so a corrupted serialiser cannot mask
// a passing verdict (compare ETS_008's stricter all-zero trailing
// guard — single-arg Float64 has no zero-padded slot, so the cond
// reads the full 8 bytes directly).
template <>
struct TestCaseTraits<cases::SomeipEts019SM> : SomeIpAnyBase<cases::SomeipEts019SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_019";
    static constexpr std::string_view kDescription =
        "echoFLOAT64 round-trip — DUT echoes the 8-byte Double 1.5";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0012;
        // CommonAPI Double wire shape: 8 bytes BE. 1.5 IEEE-754 = sign 0,
        // exponent 0x3FF, mantissa 0x8000000000000 -> 0x3FF8000000000000.
        target.payload = {0x3F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }

    // Conformant echo: case-local SSOT for the positive assertion;
    // --expect payload= overrides only for the negative harness.
    static void applyExpectedDefaults(::tc8::SomeIpExpected& e) {
        ::tc8::setExpectedPayload(e, {0x3F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    }
};

// Compile-time guard: the SFINAE detector must see this case's
// applyExpectedDefaults hook. A name/type drift would silently skip the
// case-local default at runtime and false-FAIL a conformant positive run.
static_assert(has_expected_defaults_v<TestCaseTraits<cases::SomeipEts019SM>>,
              "SOMEIP_ETS_019: applyExpectedDefaults must be detected");

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts019SM, someip_ets_019)
