#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_066_sm.h"

namespace tc8::sce::cases {

using SomeipEts066SM = ::SCE::Generated::someip_ets_066::someip_ets_066;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_066 — UTF8FIXED too_short. Tester sends
// a 63-byte payload to echoUTF8FIXED (METHOD-ID 0x0013); ets.fdepl
// pins SomeIpStringLength = 64, so the wire frame falls short by 1
// byte. UTF8 mirror of ETS_064 — CommonAPI deserialiser tries to
// read 64 bytes, only 63 available → errorOccurred_ → Error
// Response per PRS_SOMEIP_00373. Reuses ETS_001's lenient 4-path
// verdict pattern.
template <>
struct TestCaseTraits<cases::SomeipEts066SM> : SomeIpAnyBase<cases::SomeipEts066SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_066";
    static constexpr std::string_view kDescription =
        "UTF8FIXED 63-byte payload — DUT must reject (MALFORMED_MESSAGE) or ignore";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::SomeIpRpcMessage target{};
        target.method_id = 0x0013;
        // 63 raw bytes — ETS_053 baseline 64 B - 1.
        target.payload = std::vector<uint8_t>(63, 0x00);
        target.payload[0] = 0xEF;  // BOM byte 0
        target.payload[1] = 0xBB;  // BOM byte 1
        target.payload[2] = 0xBF;  // BOM byte 2
        target.payload[3] = 0x68;  // 'h'
        target.payload[4] = 0x69;  // 'i'
        // [5] = 0x00 (UTF-8 null terminator), [6..62] = 0
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts066SM, someip_ets_066)
