#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_042_sm.h"

namespace tc8::sce::cases {

using SomeipEts042SM = ::SCE::Generated::someip_ets_042::someip_ets_042;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_042 — DUT must reject (or silently ignore)
// an echoUTF16DYNAMIC Request whose SOME/IP Length header undershoots
// the actual UDP payload. Stimulus reuses the ETS_039 12-byte UTF-16
// BE baseline and sets `length_override = 0x0A` (claiming 10 bytes
// follow Length = 8 Request-ID-tail + 2 payload), while UDP carries
// 20. PRS_SOMEIP_00372 demands MALFORMED_MESSAGE; the lenient
// ETS_001/_002 pattern accepts Error Response, non-zero return_code,
// or silent ignore.
template <>
struct TestCaseTraits<cases::SomeipEts042SM> : SomeIpAnyBase<cases::SomeipEts042SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_042";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "echoUTF16DYNAMIC length too short — DUT must reject or ignore";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0016;
        target.payload = {
            0x00, 0x00, 0x00, 0x08,  // length prefix (BE)
            0xFE, 0xFF,              // BOM
            0x00, 0x68,              // 'h' UTF-16 BE
            0x00, 0x69,              // 'i' UTF-16 BE
            0x00, 0x00,              // UTF-16 null terminator
        };
        target.length_override = 0x0Au;
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts042SM, someip_ets_042)
