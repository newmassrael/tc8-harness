#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_146_neg_sm.h"

namespace tc8::sce::cases {

using SomeipEts146NegSM = ::SCE::Generated::someip_ets_146_neg::someip_ets_146_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §5.1.6 SOMEIP_ETS_146: the post-reset field readback is an application
// property — ResetInterface clears the field, so the next getFieldA must not return the
// pre-reset value. kEtsFaultResetSkip makes the harness-owned EtsImpl::resetInterface a no-op,
// so a buggy DUT surfaces a post-reset readback that still equals the last set value. The only
// faithful SOME/IP fault site — the response serialization is vendored-vsomeip-owned, but the
// reset side-effect is EtsImpl-owned. tc8-dut-only (kCapEtsFault via SomeIpEtsFaultNegBase).
template <>
struct TestCaseTraits<cases::SomeipEts146NegSM>
    : SomeIpEtsFaultNegBase<cases::SomeipEts146NegSM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_146_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of SOMEIP_ETS_146: the kEtsFaultResetSkip app fault makes "
        "resetInterface a no-op, so the post-reset getFieldA still returns the set value; a "
        "conformant DUT clears the field";

    // Arm the reset-skip fault, then drive the same get / set(0xAA) / reset / get chain the
    // positive uses. getFieldA and setFieldA are untouched by this flavor (their echoes stay
    // correct, so phases 1-3 mirror the positive), and only the post-reset getFieldA readback
    // stays at 0xAA instead of dropping to 0.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitEtsFlavorArm(cfg, iface, ::tc8::ut::kEtsFaultResetSkip);

        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        // 1. getFieldA — Method 0x40, no payload.
        ::tc8::stimulus::MethodRequestTarget get1{};
        get1.method_id = 0x0040;
        ::tc8::stimulus::emitMethodRequestAfter(iface, get1, {}, ::tc8::sce::someipUdpMethodDest(cfg));
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // 2. setFieldA(0xAA) — Method 0x42, payload [0xAA]. The setter echoes 0xAA verbatim.
        ::tc8::stimulus::MethodRequestTarget set{};
        set.method_id = 0x0042;
        set.payload   = {0xAA};
        ::tc8::stimulus::emitMethodRequestAfter(iface, set, {}, ::tc8::sce::someipUdpMethodDest(cfg));
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // 3. resetInterface — Method 0x01 Fire&Forget, no payload. The armed reset is a no-op.
        ::tc8::stimulus::MethodRequestTarget reset{};
        reset.method_id    = 0x0001;
        reset.message_type = 0x01;  // RequestNoReturn (Fire&Forget).
        ::tc8::stimulus::emitMethodRequestAfter(iface, reset, {}, ::tc8::sce::someipUdpMethodDest(cfg));

        // Spec wait: 3 s for reset to complete before re-querying.
        std::this_thread::sleep_for(std::chrono::milliseconds(3000));

        // 4. getFieldA again — with the reset skipped, the readback is still 0xAA (!= 0).
        ::tc8::stimulus::MethodRequestTarget get2{};
        get2.method_id = 0x0040;
        ::tc8::stimulus::emitMethodRequestAfter(iface, get2, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts146NegSM, someip_ets_146_neg)
