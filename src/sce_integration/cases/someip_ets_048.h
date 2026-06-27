#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_048_sm.h"

namespace tc8::sce::cases {

using SomeipEts048SM = ::SCE::Generated::someip_ets_048::someip_ets_048;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_048 — echoUTF8DYNAMIC round-trip. Tester
// sends a CommonAPI-SOMEIP UTF-8 dynamic string for ASCII "hi" to
// METHOD-ID 0x0015. The on-wire shape is `[len_BE Uint32][BOM EF BB BF]
// [char bytes][0x00]` = 10 bytes total. The trailing single null byte
// is mandatory per CommonAPI's InputStream UTF-8 path
// (capicxx-someip-runtime InputStream.cpp:251 — "if (data[itsSize - 1]
// != 0x00) errorOccurred_ = true"). ets.fdepl pins
// `SomeIpStringEncoding = utf8` + `SomeIpStringLengthWidth = 4`.
template <>
struct TestCaseTraits<cases::SomeipEts048SM> : SomeIpAnyBase<cases::SomeipEts048SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_048";
    static constexpr std::string_view kDescription =
        "echoUTF8DYNAMIC round-trip — DUT echoes UTF-8 BOM-prefixed \"hi\"";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0015;
        // 32-bit BE byte length prefix (= BOM 3 + 'h' + 'i' + null = 6),
        // UTF-8 BOM, 'h', 'i', single trailing null.
        target.payload = {
            0x00, 0x00, 0x00, 0x06,  // length prefix (BE)
            0xEF, 0xBB, 0xBF,        // UTF-8 BOM
            0x68,                    // 'h'
            0x69,                    // 'i'
            0x00,                    // trailing null terminator
        };
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }

    // Conformant echoUTF8DYNAMIC response: the canonical 10-byte echo —
    // 4-byte BE length prefix (6) + UTF-8 BOM (EF BB BF) + 'h' (68) + 'i'
    // (69) + trailing null (00). Case-local SSOT for the positive assertion
    // (the cond reads expected.payload_view()); --expect payload= overrides
    // it only for the negative harness, keeping the case self-contained
    // across all drivers.
    static void applyExpectedDefaults(::tc8::SomeIpExpected& e) {
        ::tc8::setExpectedPayload(e, {
            0x00, 0x00, 0x00, 0x06,  // length prefix (BE) = 6
            0xEF, 0xBB, 0xBF,        // UTF-8 BOM
            0x68,                    // 'h'
            0x69,                    // 'i'
            0x00,                    // trailing null terminator
        });
    }
};

// Compile-time guard: the SFINAE detector must see this case's
// applyExpectedDefaults hook. A name/type drift would silently skip the
// case-local default at runtime and false-FAIL a conformant positive run.
static_assert(has_expected_defaults_v<TestCaseTraits<cases::SomeipEts048SM>>,
              "SOMEIP_ETS_048: applyExpectedDefaults must be detected");

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts048SM, someip_ets_048)
