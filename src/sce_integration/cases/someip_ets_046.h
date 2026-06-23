#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_046_sm.h"

namespace tc8::sce::cases {

using SomeipEts046SM = ::SCE::Generated::someip_ets_046::someip_ets_046;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_046 — echoUTF16FIXED round-trip. Tester
// sends a CommonAPI-SOMEIP fixed-length 64-byte UTF-16 BE string for
// ASCII "hi" to METHOD-ID 0x0014. The on-wire shape carries no length
// prefix — `SomeIpStringLengthWidth = 0` + `SomeIpStringLength = 64`
// in ets.fdepl pin the 64-byte fixed payload (per upstream
// all_features.fdepl block-comment "If LengthWidth == 0, the length
// of the string has StringLength bytes"). Layout: BOM (FE FF) +
// 'h' (00 68) + 'i' (00 69) + UTF-16 null terminator (00 00) + 56 B
// of zero padding = 64 B total. The UTF-16 null terminator is
// mandatory per CommonAPI's InputStream walk-back loop
// (capicxx-someip-runtime InputStream.cpp:259-263); the trailing
// padding zeros sit beyond the terminator and are part of the
// fixed-width frame, not the decoded string content.
template <>
struct TestCaseTraits<cases::SomeipEts046SM> : SomeIpAnyBase<cases::SomeipEts046SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_046";
    static constexpr std::string_view kDescription =
        "echoUTF16FIXED round-trip — DUT echoes 64-byte UTF-16 BE BOM-prefixed \"hi\"";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0014;
        // 64 raw bytes, no length prefix. BOM + 'h' + 'i' + UTF-16
        // null terminator + 56 B zero padding.
        target.payload = std::vector<uint8_t>(64, 0x00);
        target.payload[0]  = 0xFE;  // BOM hi
        target.payload[1]  = 0xFF;  // BOM lo
        target.payload[2]  = 0x00;  // 'h' hi
        target.payload[3]  = 0x68;  // 'h' lo
        target.payload[4]  = 0x00;  // 'i' hi
        target.payload[5]  = 0x69;  // 'i' lo
        // [6..7] = 00 00 (UTF-16 null terminator), [8..63] = 0
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }

    // Conformant echoUTF16FIXED response: the 64-byte fixed frame echoed
    // unchanged — BOM (FE FF) + 'h' (00 68) + 'i' (00 69) + UTF-16 null
    // (00 00) + 56 B zero padding. Case-local SSOT for the positive
    // assertion (the cond reads expected.payload_view()); --expect payload=
    // overrides it only for the negative harness, keeping the case
    // self-contained across all drivers.
    static void applyExpectedDefaults(::tc8::SomeIpExpected& e) {
        ::tc8::setExpectedPayload(e, {
            0xFE, 0xFF, 0x00, 0x68, 0x00, 0x69, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        });
    }
};

// Compile-time guard: the SFINAE detector must see this case's
// applyExpectedDefaults hook. A name/type drift would silently skip the
// case-local default at runtime and false-FAIL a conformant positive run.
static_assert(has_expected_defaults_v<TestCaseTraits<cases::SomeipEts046SM>>,
              "SOMEIP_ETS_046: applyExpectedDefaults must be detected");

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts046SM, someip_ets_046)
