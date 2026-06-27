#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_073_sm.h"

namespace tc8::sce::cases {

using SomeipEts073SM = ::SCE::Generated::someip_ets_073::someip_ets_073;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_073 — DUT must emit *some* method response
// for an echoUNION Request whose inner union-type discriminant lies
// beyond the declared 6-type range (Boolean/uint8/uint16/uint32/sint8
// /sint16 per fidl typeCollection EtsTypes). Stimulus reuses the
// ETS_038 Type 2 baseline but corrupts payload byte 7 from 0x02 to
// 0x07. SOME/IP Length stays self-consistent so the frame reaches
// CommonAPI; the Variant decoder logs "ApplyStreamVisitor type not
// found" / "ApplyVoidIndexVisitor type not found" warnings but the
// dispatcher still emits a method response (Linux DUT: msg_type 0x80
// + return_code 0x00 with the Variant contents degraded by the
// unknown discriminant).
//
// Spec wording is "DUT: returns method response messages with the
// correct union type and adjusted padding" — a positive-shape pass
// criteria, NOT a malformed-rejection axis like ETS_070..072. Lenient
// verdict accepts any method response (msg_type 0x80 OR 0x81) on
// method_id 0x0019; only silent ignore (deadline) lands on fail —
// that would imply the DUT crashed or dropped the frame entirely on
// the wrong-type field.
template <>
struct TestCaseTraits<cases::SomeipEts073SM> : SomeIpAnyBase<cases::SomeipEts073SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_073";
    static constexpr std::string_view kDescription =
        "echoUNION inner union-type out of range — DUT must respond (any return_code)";

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
            // unionType_BE = 0x00000007 (lies — out of range; spec
            // typeCollection EtsTypes only declares discriminants 1..6)
            0x00, 0x00, 0x00, 0x07,
            // value = 0x42 (uint8)
            0x42,
        };
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts073SM, someip_ets_073)
