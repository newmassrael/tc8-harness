#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_058_sm.h"

namespace tc8::sce::cases {

using SomeipEts058SM = ::SCE::Generated::someip_ets_058::someip_ets_058;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_058 — Length_way_too_long. Tester sends
// echoUINT8 (METHOD-ID 0x0008) with SOME/IP Length header forced to
// 0x00010000 (claims 65536 bytes follow Request ID, while UDP only
// carries 9 bytes after the header). Per PRS_SOMEIP_00902 /
// PRS_SOMEIP_00191 the DUT must reject with MALFORMED_MESSAGE or
// ignore. Reuses ETS_001's lenient 4-path verdict pattern; this is
// the upper-magnitude length axis variant of ETS_001 (0x100) /
// ETS_002 (0x20).
template <>
struct TestCaseTraits<cases::SomeipEts058SM> : SomeIpAnyBase<cases::SomeipEts058SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_058";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "SOME/IP Length way too long (0x10000) — DUT must reject or ignore";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0008;
        target.payload = {0x42};
        // Length = 0x10000 (65536) — far exceeds the ~1500 B UDP MTU
        // and the actual 9 B (Request ID + 1 B payload) the datagram
        // carries. Larger-magnitude variant of ETS_001 (0x100) /
        // ETS_002 (0x20); both lenient-verdict 4-path.
        target.length_override = 0x00010000u;
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts058SM, someip_ets_058)
