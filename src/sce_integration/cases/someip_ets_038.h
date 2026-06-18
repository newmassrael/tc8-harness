#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_038_sm.h"

namespace tc8::sce::cases {

using SomeipEts038SM = ::SCE::Generated::someip_ets_038::someip_ets_038;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_038 — echoUNION. Tester sends a SOME/IP
// union encoded with the runtime defaults (capicxx-someip-runtime
// VariantDeployment fallback when no per-param fdepl deployment is
// generated): unionLengthWidth = 4, unionTypeWidth = 4,
// unionDefaultOrder = true (length first, type second). Spec p401-420
// echoUNION row mandates the matching wire shape (UInt32 len, UInt32
// type, value-of-type) and lists six type discriminants:
//   Type 1 = Boolean, Type 2 = uint8, Type 3 = uint16,
//   Type 4 = uint32, Type 5 = sint8, Type 6 = sint16.
// CommonAPI Variant uses 1-based wire type tags in declaration order
// (decoded as `valueType_ = maxValueType - itsType + 1`); the fidl
// declaration order matches the spec discriminants.
//
// This case exercises Type 2 (uint8 = 0x42):
//   Wire (9 bytes): [00 00 00 01][00 00 00 02][42]
//                    ^len_BE=1   ^type_BE=2    ^value
// DUT echoes the request unchanged (PRS_SOMEIP_00119 + PRS_SOMEIP_00126).
template <>
struct TestCaseTraits<cases::SomeipEts038SM> : SomeIpAnyBase<cases::SomeipEts038SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_038";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "echoUNION — DUT echoes a SOME/IP union (Type 2 = uint8 = 0x42) unchanged";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0019;
        target.payload = {
            // unionLength_BE = 0x00000001 (sizeof(uint8) = 1 byte)
            0x00, 0x00, 0x00, 0x01,
            // unionType_BE = 0x00000002 (Type 2 = uint8 per spec p401-420)
            0x00, 0x00, 0x00, 0x02,
            // value = 0x42 (uint8)
            0x42,
        };
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }

    // Conformant echo: case-local SSOT for the positive assertion;
    // --expect payload= overrides only for the negative harness.
    static void applyExpectedDefaults(::tc8::SomeIpExpected& e) {
        ::tc8::setExpectedPayload(e, {0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x42});
    }
};

// Compile-time guard: the SFINAE detector must see this case's
// applyExpectedDefaults hook. A name/type drift would silently skip the
// case-local default at runtime and false-FAIL a conformant positive run.
static_assert(has_expected_defaults_v<TestCaseTraits<cases::SomeipEts038SM>>,
              "SOMEIP_ETS_038: applyExpectedDefaults must be detected");

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts038SM, someip_ets_038)
