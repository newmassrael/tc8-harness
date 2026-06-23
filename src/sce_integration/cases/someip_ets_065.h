#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_065_sm.h"

namespace tc8::sce::cases {

using SomeipEts065SM = ::SCE::Generated::someip_ets_065::someip_ets_065;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_065 — UTF8FIXED too_long. Tester sends
// a 65-byte payload to echoUTF8FIXED (METHOD-ID 0x0013); ets.fdepl
// pins SomeIpStringLength = 64, so the wire frame exceeds the fixed
// frame size by 1 byte. UTF8 mirror of ETS_063 — same lenient
// verdict shape (any method response → pass) since the Linux DUT
// echoes the canonical 64 B frame after stripping the trailing
// extra byte (per ETS_047 odd-byte-axis precedent on the UTF16
// path; UTF8 fixed-frame deserialiser exhibits the same behaviour).
template <>
struct TestCaseTraits<cases::SomeipEts065SM> : SomeIpAnyBase<cases::SomeipEts065SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_065";
    static constexpr std::string_view kDescription =
        "UTF8FIXED 65-byte payload — DUT must respond (any return_code)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0013;
        // 65 raw bytes — ETS_053 baseline 64 B + 1 trailing 0xFF.
        target.payload = std::vector<uint8_t>(65, 0x00);
        target.payload[0] = 0xEF;  // BOM byte 0
        target.payload[1] = 0xBB;  // BOM byte 1
        target.payload[2] = 0xBF;  // BOM byte 2
        target.payload[3] = 0x68;  // 'h'
        target.payload[4] = 0x69;  // 'i'
        // [5] = 0x00 (UTF-8 null terminator), [6..63] = 0
        target.payload[64] = 0xFF;  // extra byte past the fixed frame
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts065SM, someip_ets_065)
