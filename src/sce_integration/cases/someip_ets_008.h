#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_008_sm.h"

namespace tc8::sce::cases {

using SomeipEts008SM = ::SCE::Generated::someip_ets_008::someip_ets_008;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_008 — echoCommonDatatypes. DUT receives a
// nine-tuple (Bool/UInt8/UInt16/UInt32/Int8/Int16/Int32/Float/Double)
// and replies with the same values in REVERSED order
// (res1=arg9, res2=arg8, ..., res9=arg1) per ets.fidl §5.1.4.2.1.
//
// Stimulus = 27-byte payload, all-zero except arg9 = Double 1.5
// (BE 0x3FF8000000000000 at request offset 19..26). After reversal
// the response carries res1 = 1.5 at offset 0..7; everything else
// stays zero. Verifying both the distinctive Double prefix AND the
// trailing zeros (within the 16-byte capture cap) catches three
// failure modes: missing reversal (Double would land at offset 19
// instead of 0), corrupt Double serialisation (wrong wire bits), and
// any of arg2..arg8 not echoed faithfully (a non-zero leak in 8..15).
template <>
struct TestCaseTraits<cases::SomeipEts008SM> : SomeIpAnyBase<cases::SomeipEts008SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_008";
    static constexpr std::string_view kDescription =
        "echoCommonDatatypes — DUT echoes nine-tuple (Bool..Double) in REVERSED order";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0023;
        // 27-byte CommonAPI payload, no alignment padding:
        //   Bool/UInt8 1B each, UInt16 2B BE, UInt32 4B BE, Int8 1B,
        //   Int16 2B BE, Int32 4B BE, Float 4B BE, Double 8B BE.
        // All-zero arg1..arg8; arg9 = 1.5 (Double BE 0x3FF8000000000000)
        // at offset 19..26 — the only distinctive prefix in the request.
        target.payload = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x3F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }

    // Conformant echoCommonDatatypes response: the nine-tuple echoed in
    // REVERSED order, so res1 = arg9 = Double 1.5 (BE 0x3FF8000000000000)
    // lands at offset 0..7 and res2..res9 (arg8..arg1, all-zero) fill the
    // remaining 19 bytes — 27 bytes total. Case-local SSOT for the positive
    // assertion (the cond reads expected.payload_view()); --expect payload=
    // overrides it only for the negative harness, keeping the case
    // self-contained across all drivers.
    static void applyExpectedDefaults(::tc8::SomeIpExpected& e) {
        ::tc8::setExpectedPayload(e, {
            0x3F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        });
    }
};

// Compile-time guard: the SFINAE detector must see this case's
// applyExpectedDefaults hook. A name/type drift would silently skip the
// case-local default at runtime and false-FAIL a conformant positive run.
static_assert(has_expected_defaults_v<TestCaseTraits<cases::SomeipEts008SM>>,
              "SOMEIP_ETS_008: applyExpectedDefaults must be detected");

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts008SM, someip_ets_008)
