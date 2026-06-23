#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_166_sm.h"

namespace tc8::sce::cases {

using SomeipEts166SM = ::SCE::Generated::someip_ets_166::someip_ets_166;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_166 — Trigger DUT to send TestFieldUINT8
// using getter/setter methods; DUT must respond correctly. Per
// PRS_SOMEIPSD_00357 / 00360 / 00361 / PRS_SOMEIP_00180 the DUT shall
// echo the current field value on get and confirm the new value on set.
//
// Wire shape: TC8 §5.1.4 Table 2 reserves Method 0x26 (TestFieldUINT8
// Getter) + 0x27 (Setter) for spec-canonical interop. The tc8-dut
// firmware's `EnhancedTestability` uses `fieldA` at Method 0x40 (Getter)
// + 0x42 (Setter) — same UInt8 wire shape, different IDs. This trait
// stimulates fieldA's IDs because the conformance signal is the
// Request/Response wire-shape correspondence on a UInt8 field, not the
// canonical Method ID. Lifts ETS_146's get/set/get sequence (without the
// reset step).
template <>
struct TestCaseTraits<cases::SomeipEts166SM> : SomeIpAnyBase<cases::SomeipEts166SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_166";
    static constexpr std::string_view kDescription =
        "TestFieldUINT8 getter / setter / getter — DUT echoes set value";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        // 1. getFieldA — Method 0x40, no payload.
        ::tc8::stimulus::MethodRequestTarget get1{};
        get1.method_id = 0x0040;
        ::tc8::stimulus::emitMethodRequestAfter(iface, get1);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // 2. setFieldA(0x55) — Method 0x42, payload [0x55].
        ::tc8::stimulus::MethodRequestTarget set{};
        set.method_id = 0x0042;
        set.payload   = {0x55};
        ::tc8::stimulus::emitMethodRequestAfter(iface, set);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // 3. getFieldA again — should now return 0x55.
        ::tc8::stimulus::MethodRequestTarget get2{};
        get2.method_id = 0x0040;
        ::tc8::stimulus::emitMethodRequestAfter(iface, get2);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts166SM, someip_ets_166)
