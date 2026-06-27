#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_043_sm.h"

namespace tc8::sce::cases {

using SomeipEts043SM = ::SCE::Generated::someip_ets_043::someip_ets_043;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_043 — echoUTF16DYNAMIC with odd byte
// BEFORE termination. Tester sends a 13-byte payload whose 4-byte
// length prefix declares 9 bytes of UTF-16 BE content. The 9 bytes
// are BOM + 'h' + 1 odd byte (0xFF) + 'i' + UTF-16 null terminator,
// so the last 2 bytes ARE the 00 00 null pair — CommonAPI's
// InputStream walk-back loop
// (capicxx-someip-runtime InputStream.cpp:259-263) exits immediately
// at itsSize=9, the `itsSize % 2 != 0` gate trips errorOccurred_,
// and the dispatcher emits Error Response (msg_type 0x81 +
// return_code 0x09 E_MALFORMED_MESSAGE) per PRS_SOMEIP_00087.
// Lenient ETS_001/_002 verdict pattern accepts Error Response,
// non-zero return_code, or silent ignore.
template <>
struct TestCaseTraits<cases::SomeipEts043SM> : SomeIpAnyBase<cases::SomeipEts043SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_043";
    static constexpr std::string_view kDescription =
        "echoUTF16DYNAMIC odd-before-termination — DUT must reject or ignore";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0016;
        target.payload = {
            0x00, 0x00, 0x00, 0x09,  // length prefix (BE) — 9 bytes follow
            0xFE, 0xFF,              // BOM
            0x00, 0x68,              // 'h' UTF-16 BE
            0xFF,                    // odd byte — lands BEFORE the null pair
            0x00, 0x69,              // 'i' UTF-16 BE
            0x00, 0x00,              // UTF-16 null terminator (last 2 bytes)
        };
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts043SM, someip_ets_043)
