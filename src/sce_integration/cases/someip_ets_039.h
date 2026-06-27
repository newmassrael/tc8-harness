#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_039_sm.h"

namespace tc8::sce::cases {

using SomeipEts039SM = ::SCE::Generated::someip_ets_039::someip_ets_039;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_039 — echoUTF16DYNAMIC round-trip. Tester
// sends a CommonAPI-SOMEIP UTF-16 BE dynamic string for ASCII "hi" to
// METHOD-ID 0x0016. The on-wire shape is `[len_BE Uint32][BOM 0xFEFF]
// [char bytes UTF-16 BE][2-byte UTF-16 null]` = 12 bytes total. The
// trailing null terminator is mandated by CommonAPI's InputStream
// (capicxx-someip-runtime/src/CommonAPI/SomeIP/InputStream.cpp:259-263:
// the deserializer walks backwards stripping bytes until it finds two
// consecutive zeros, then errors out if the remaining size is odd).
// Without the null terminator the DUT replies with msg_type 0x81 +
// return_code 0x09 (E_MALFORMED_MESSAGE) instead of an echo. ets.fdepl
// pins `SomeIpStringEncoding = utf16be` + `SomeIpStringLengthWidth = 4`.
template <>
struct TestCaseTraits<cases::SomeipEts039SM> : SomeIpAnyBase<cases::SomeipEts039SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_039";
    static constexpr std::string_view kDescription =
        "echoUTF16DYNAMIC round-trip — DUT echoes UTF-16 BE BOM-prefixed \"hi\"";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0016;
        // 32-bit BE byte length prefix (= BOM 2 + 'h' 2 + 'i' 2 + null 2
        // = 8), BOM 0xFEFF, UTF-16 BE chars, UTF-16 null terminator.
        target.payload = {
            0x00, 0x00, 0x00, 0x08,  // length prefix (BE)
            0xFE, 0xFF,              // BOM
            0x00, 0x68,              // 'h' UTF-16 BE
            0x00, 0x69,              // 'i' UTF-16 BE
            0x00, 0x00,              // UTF-16 null terminator
        };
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }

    // Conformant echoUTF16DYNAMIC response: the canonical 12-byte echo —
    // 4-byte BE length prefix (8) + BOM (FE FF) + 'h' (00 68) + 'i' (00 69)
    // + UTF-16 null (00 00). Case-local SSOT for the positive assertion (the
    // cond reads expected.payload_view()); --expect payload= overrides it
    // only for the negative harness, keeping the case self-contained across
    // all drivers.
    static void applyExpectedDefaults(::tc8::SomeIpExpected& e) {
        ::tc8::setExpectedPayload(e, {
            0x00, 0x00, 0x00, 0x08,  // length prefix (BE) = 8
            0xFE, 0xFF,              // BOM
            0x00, 0x68,              // 'h'
            0x00, 0x69,              // 'i'
            0x00, 0x00,              // UTF-16 null terminator
        });
    }
};

// Compile-time guard: the SFINAE detector must see this case's
// applyExpectedDefaults hook. A name/type drift would silently skip the
// case-local default at runtime and false-FAIL a conformant positive run.
static_assert(has_expected_defaults_v<TestCaseTraits<cases::SomeipEts039SM>>,
              "SOMEIP_ETS_039: applyExpectedDefaults must be detected");

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts039SM, someip_ets_039)
