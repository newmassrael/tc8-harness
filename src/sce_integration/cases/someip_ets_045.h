#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_045_sm.h"

namespace tc8::sce::cases {

using SomeipEts045SM = ::SCE::Generated::someip_ets_045::someip_ets_045;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_045 — DUT must reject (or silently ignore)
// an echoUTF16DYNAMIC Request whose payload carries a corrupt UTF-16
// BOM (0xFEFF -> 0xDEAD). The SOME/IP Length stays self-consistent
// so the frame reaches CommonAPI's InputStream UTF-16 deserializer
// (capicxx-someip-runtime InputStream.cpp:248-281); checkBom fails,
// errorOccurred_ trips, and the dispatcher emits an Error Response
// (msg_type 0x81 + return_code 0x09 E_MALFORMED_MESSAGE) per
// PRS_SOMEIP_00087. Lenient ETS_001/_002 verdict pattern accepts
// Error Response, non-zero return_code, or silent ignore.
template <>
struct TestCaseTraits<cases::SomeipEts045SM> : SomeIpAnyBase<cases::SomeipEts045SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_045";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "echoUTF16DYNAMIC wrong BOM — DUT must reject or ignore";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0016;
        // ETS_039 baseline with the UTF-16 BOM (FE FF) mutated to DE AD —
        // CommonAPI's InputStream::checkBom rejects the request and the
        // dispatcher translates to E_MALFORMED_MESSAGE.
        target.payload = {
            0x00, 0x00, 0x00, 0x08,  // length prefix (BE)
            0xDE, 0xAD,              // wrong BOM (was FE FF)
            0x00, 0x68,              // 'h' UTF-16 BE
            0x00, 0x69,              // 'i' UTF-16 BE
            0x00, 0x00,              // UTF-16 null terminator
        };
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts045SM, someip_ets_045)
