#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_064_sm.h"

namespace tc8::sce::cases {

using SomeipEts064SM = ::SCE::Generated::someip_ets_064::someip_ets_064;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_064 — UTF16FIXED too_short. Tester sends
// a 63-byte payload to echoUTF16FIXED (METHOD-ID 0x0014); ets.fdepl
// pins SomeIpStringLength = 64, so the wire frame falls short by 1
// byte. CommonAPI's deserializer reads exactly 64 bytes — only 63
// available → errorOccurred_ → dispatcher emits Error Response per
// PRS_SOMEIP_00373. Reuses ETS_001's lenient 4-path verdict pattern
// (Error Response, non-zero return_code, deadline → pass; only
// return_code 0x00 echo → fail).
template <>
struct TestCaseTraits<cases::SomeipEts064SM> : SomeIpAnyBase<cases::SomeipEts064SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_064";
    static constexpr std::string_view kDescription =
        "UTF16FIXED 63-byte payload — DUT must reject (MALFORMED_MESSAGE) or ignore";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0014;
        // 63 raw bytes — ETS_046 baseline 64 B - 1. SOME/IP Length
        // self-consistent at 8 + 63 = 71 so the frame reaches CommonAPI.
        target.payload = std::vector<uint8_t>(63, 0x00);
        target.payload[0]  = 0xFE;  // BOM hi
        target.payload[1]  = 0xFF;  // BOM lo
        target.payload[2]  = 0x00;  // 'h' hi
        target.payload[3]  = 0x68;  // 'h' lo
        target.payload[4]  = 0x00;  // 'i' hi
        target.payload[5]  = 0x69;  // 'i' lo
        // [6..7] = 00 00 (UTF-16 null terminator), [8..62] = 0
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts064SM, someip_ets_064)
