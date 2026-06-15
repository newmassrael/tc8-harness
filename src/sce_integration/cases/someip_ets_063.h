#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_063_sm.h"

namespace tc8::sce::cases {

using SomeipEts063SM = ::SCE::Generated::someip_ets_063::someip_ets_063;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_063 — UTF16FIXED too_long. Tester sends
// a 65-byte payload to echoUTF16FIXED (METHOD-ID 0x0014); ets.fdepl
// pins SomeIpStringLength = 64, so the wire frame exceeds the fixed
// frame size by 1 byte. Per PRS_SOMEIP_00911 the DUT must reject with
// MALFORMED_MESSAGE; ETS_047 (positive odd-byte axis) showed Linux
// DUT echoes the canonical 64 B frame instead, so the verdict shape
// uses ETS_073's lenient-positive pattern (any method response on
// method_id 0x0014 → pass; only silent ignore lands on fail).
template <>
struct TestCaseTraits<cases::SomeipEts063SM> : SomeIpAnyBase<cases::SomeipEts063SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_063";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "UTF16FIXED 65-byte payload — DUT must respond (any return_code)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0014;
        // 65 raw bytes — ETS_046 baseline 64 B + 1 trailing 0xFF.
        target.payload = std::vector<uint8_t>(65, 0x00);
        target.payload[0]  = 0xFE;  // BOM hi
        target.payload[1]  = 0xFF;  // BOM lo
        target.payload[2]  = 0x00;  // 'h' hi
        target.payload[3]  = 0x68;  // 'h' lo
        target.payload[4]  = 0x00;  // 'i' hi
        target.payload[5]  = 0x69;  // 'i' lo
        // [6..7] = 00 00 (UTF-16 null terminator), [8..63] = 0
        target.payload[64] = 0xFF;  // extra byte past the fixed frame
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts063SM, someip_ets_063)
