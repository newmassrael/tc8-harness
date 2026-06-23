#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_146_sm.h"

namespace tc8::sce::cases {

using SomeipEts146SM = ::SCE::Generated::someip_ets_146::someip_ets_146;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_146 — TestField get / set / reset cycle.
// Stimulus chains four UDP Method Requests on SERVICE-ID-1: getFieldA,
// setFieldA(0xAA), resetInterface (Fire&Forget), then getFieldA again.
// Per PRS_SOMEIPSD_00356 / PRS_SOMEIP_00170 the post-reset value must
// differ from the value last set. tc8-dut's `EtsImpl::resetInterface`
// override clears `fieldA_` to 0 so the second getFieldA Response carries
// payload_snapshot[0] == 0 (≠ 0xAA).
template <>
struct TestCaseTraits<cases::SomeipEts146SM> : SomeIpAnyBase<cases::SomeipEts146SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_146";
    static constexpr std::string_view kDescription =
        "getFieldA / setFieldA(0xAA) / resetInterface / getFieldA — post-reset value differs";

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

        // 2. setFieldA(0xAA) — Method 0x42, payload [0xAA].
        ::tc8::stimulus::MethodRequestTarget set{};
        set.method_id = 0x0042;
        set.payload   = {0xAA};
        ::tc8::stimulus::emitMethodRequestAfter(iface, set);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // 3. resetInterface — Method 0x01 Fire&Forget, no payload.
        ::tc8::stimulus::MethodRequestTarget reset{};
        reset.method_id    = 0x0001;
        reset.message_type = 0x01;  // RequestNoReturn (Fire&Forget).
        ::tc8::stimulus::emitMethodRequestAfter(iface, reset);

        // Spec wait: 3 s for reset to complete before re-querying.
        std::this_thread::sleep_for(std::chrono::milliseconds(3000));

        // 4. getFieldA again.
        ::tc8::stimulus::MethodRequestTarget get2{};
        get2.method_id = 0x0040;
        ::tc8::stimulus::emitMethodRequestAfter(iface, get2);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts146SM, someip_ets_146)
