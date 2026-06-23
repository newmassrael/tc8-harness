#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_031_sm.h"

namespace tc8::sce::cases {

using SomeipEts031SM = ::SCE::Generated::someip_ets_031::someip_ets_031;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_031 — echoUINT8Array8BitLength
// round-trip. Same shape as _028/_029 but the array's wire length
// prefix is 8 bits (ets.fdepl: SomeIpArrayLengthWidth = 1). Method
// ID 0x003E (METHOD-ID-31-SI-1 per spec Table 1).
template <>
struct TestCaseTraits<cases::SomeipEts031SM> : SomeIpAnyBase<cases::SomeipEts031SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_031";
    static constexpr std::string_view kDescription =
        "echoUINT8Array8BitLength round-trip — DUT echoes the array";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x003E;
        // CommonAPI UInt8[] with 8-bit length prefix:
        // [len = 0x03] [0x42 0x43 0x44]. payload_len = 4.
        target.payload = {0x03, 0x42, 0x43, 0x44};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }

    // Conformant echo: case-local SSOT for the positive assertion;
    // --expect payload= overrides only for the negative harness.
    static void applyExpectedDefaults(::tc8::SomeIpExpected& e) {
        ::tc8::setExpectedPayload(e, {0x03, 0x42, 0x43, 0x44});
    }
};

// Compile-time guard: the SFINAE detector must see this case's
// applyExpectedDefaults hook. A name/type drift would silently skip the
// case-local default at runtime and false-FAIL a conformant positive run.
static_assert(has_expected_defaults_v<TestCaseTraits<cases::SomeipEts031SM>>,
              "SOMEIP_ETS_031: applyExpectedDefaults must be detected");

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts031SM, someip_ets_031)
