#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_067_sm.h"

namespace tc8::sce::cases {

using SomeipEts067SM = ::SCE::Generated::someip_ets_067::someip_ets_067;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_067 — UINT8Array_with_Length_0_strips_Payload.
// Tester sends echoUINT8Array (METHOD-ID 0x0009) with the wire payload
// set to a 32-bit BE length prefix of zero and no array elements. The
// SOME/IP Length header is the natural 8 + 4 = 12 (no length_override).
// Per PRS_SOMEIP_00375 / PRS_SOMEIP_00377 / PRS_SOMEIP_00114 the DUT
// must respond with an empty UINT8Array (payload either truly empty
// or carrying only the 4-byte zero length prefix). Linux DUT
// (CommonAPI-SOMEIP) echoes the 4-byte zero length prefix.
template <>
struct TestCaseTraits<cases::SomeipEts067SM> : SomeIpAnyBase<cases::SomeipEts067SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_067";
    static constexpr std::string_view kDescription =
        "echoUINT8Array with array length zero — DUT echoes empty array";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0009;
        // 32-bit BE array length = 0 (no elements follow). Wire payload =
        // 4 bytes; SOME/IP Length = 8 + 4 = 12 (default formula).
        target.payload = {0x00, 0x00, 0x00, 0x00};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts067SM, someip_ets_067)
