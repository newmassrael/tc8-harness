#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_030_sm.h"

namespace tc8::sce::cases {

using SomeipEts030SM = ::SCE::Generated::someip_ets_030::someip_ets_030;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_030 — echoUINT8Array2Dim round-trip.
// Tester sends 2 sub-arrays each holding 1 UInt8 element to METHOD-ID
// 0x0035; both outer and inner dimensions carry a 32-bit BE byte
// length prefix per ets.fdepl `SomeIpArrayLengthWidth = 4`. DUT
// echoes the full nested structure back. Wire-format invariant per
// PRS_SOMEIP_00101/00102.
//
// Wire layout (14 bytes total payload):
//   [0..3]   outer_len_BE   = 0x0000000A (10 bytes of inner data)
//   [4..7]   inner1_len_BE  = 0x00000001
//   [8]      inner1[0]      = 0x42
//   [9..12]  inner2_len_BE  = 0x00000001
//   [13]     inner2[0]      = 0x43
template <>
struct TestCaseTraits<cases::SomeipEts030SM> : SomeIpAnyBase<cases::SomeipEts030SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_030";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "echoUINT8Array2Dim round-trip — 2 sub-arrays each holding 1 UInt8";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0035;
        target.payload = {
            0x00, 0x00, 0x00, 0x0A,  // outer byte length
            0x00, 0x00, 0x00, 0x01,  // inner #1 byte length
            0x42,                    // inner #1 data
            0x00, 0x00, 0x00, 0x01,  // inner #2 byte length
            0x43,                    // inner #2 data
        };
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }

    // Conformant echo: case-local SSOT for the positive assertion;
    // --expect payload= overrides only for the negative harness.
    static void applyExpectedDefaults(::tc8::SomeIpExpected& e) {
        ::tc8::setExpectedPayload(e, {0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x01, 0x42, 0x00, 0x00, 0x00, 0x01, 0x43});
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts030SM, someip_ets_030)
