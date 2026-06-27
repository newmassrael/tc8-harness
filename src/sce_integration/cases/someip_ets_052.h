#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_052_sm.h"

namespace tc8::sce::cases {

using SomeipEts052SM = ::SCE::Generated::someip_ets_052::someip_ets_052;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_052 — DUT must reject (or silently ignore)
// an echoUTF8DYNAMIC Request whose payload carries a corrupt UTF-8 BOM
// (EF BB BF -> DE AD BE). The SOME/IP Length stays self-consistent
// so the frame reaches CommonAPI's InputStream UTF-8 deserializer
// (capicxx-someip-runtime InputStream.cpp:248-256); checkBom fails,
// errorOccurred_ trips, and the dispatcher emits an Error Response
// (msg_type 0x81 + return_code 0x09 E_MALFORMED_MESSAGE) per
// PRS_SOMEIP_00087. Lenient ETS_001/_002 verdict pattern accepts
// Error Response, non-zero return_code, or silent ignore.
template <>
struct TestCaseTraits<cases::SomeipEts052SM> : SomeIpAnyBase<cases::SomeipEts052SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_052";
    static constexpr std::string_view kDescription =
        "echoUTF8DYNAMIC wrong BOM — DUT must reject or ignore";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0015;
        // ETS_048 baseline with the UTF-8 BOM (EF BB BF) mutated to
        // DE AD BE — CommonAPI's InputStream::checkBom rejects and the
        // dispatcher translates to E_MALFORMED_MESSAGE.
        target.payload = {
            0x00, 0x00, 0x00, 0x06,  // length prefix (BE)
            0xDE, 0xAD, 0xBE,        // wrong BOM (was EF BB BF)
            0x68,                    // 'h'
            0x69,                    // 'i'
            0x00,                    // trailing null terminator
        };
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts052SM, someip_ets_052)
