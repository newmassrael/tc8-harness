#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_040_sm.h"

namespace tc8::sce::cases {

using SomeipEts040SM = ::SCE::Generated::someip_ets_040::someip_ets_040;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_040 — DUT must reject (or silently ignore)
// an echoUTF16DYNAMIC Request whose SOME/IP Length header overshoots the
// actual UDP payload. Stimulus reuses the ETS_039 12-byte UTF-16 BE
// baseline (length prefix + BOM + 'h' + 'i' + UTF-16 null) and sets
// `length_override = 0x100` so the SOME/IP header claims 256 bytes
// follow Request ID while UDP only carries 12. vsomeip's parser
// detects the mismatch and drops the frame (or returns
// MALFORMED_MESSAGE depending on stack); both paths satisfy the spec
// pass criteria via the lenient ETS_001/_002 verdict pattern.
template <>
struct TestCaseTraits<cases::SomeipEts040SM> : SomeIpAnyBase<cases::SomeipEts040SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_040";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "echoUTF16DYNAMIC length too long — DUT must reject or ignore";

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
        target.length_override = 0x100u;
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts040SM, someip_ets_040)
