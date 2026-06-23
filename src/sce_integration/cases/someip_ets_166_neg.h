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

#include "someip_ets_166_neg_sm.h"

namespace tc8::sce::cases {

using SomeipEts166NegSM = ::SCE::Generated::someip_ets_166_neg::someip_ets_166_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §5.1.6 SOMEIP_ETS_166: the post-set field readback is an application
// property — the EnhancedTestability service stores the set value and the getter echoes it.
// kEtsFaultFieldValueWrong makes the harness-owned EtsImpl field getter return the stored
// value bit-flipped (!= the set value), so a buggy DUT surfaces a readback that does not echo
// what was set. The only faithful SOME/IP fault site — the response serialization is
// vendored-vsomeip-owned, but the field value the getter returns is EtsImpl-owned, and an
// ingress/egress wire mutation would make the DUT faithfully report the rewritten value.
// tc8-dut-only (kCapEtsFault via SomeIpEtsFaultNegBase).
template <>
struct TestCaseTraits<cases::SomeipEts166NegSM>
    : SomeIpEtsFaultNegBase<cases::SomeipEts166NegSM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_166_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of SOMEIP_ETS_166: the kEtsFaultFieldValueWrong app fault makes the "
        "field getter return a value that does not echo what setField stored; a conformant DUT "
        "echoes the set value";

    // Arm the field-getter value fault, then drive the same get / set(0x55) / get chain the
    // positive uses. The setter is untouched (its echo stays correct, so phase 3 mirrors the
    // positive), and only the post-set getFieldA readback is bit-flipped (!= 0x55).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitEtsFlavorArm(cfg, iface, ::tc8::ut::kEtsFaultFieldValueWrong);

        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        // 1. getFieldA — Method 0x40, no payload.
        ::tc8::stimulus::MethodRequestTarget get1{};
        get1.method_id = 0x0040;
        ::tc8::stimulus::emitMethodRequestAfter(iface, get1);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // 2. setFieldA(0x55) — Method 0x42, payload [0x55]. The setter echoes 0x55 verbatim.
        ::tc8::stimulus::MethodRequestTarget set{};
        set.method_id = 0x0042;
        set.payload   = {0x55};
        ::tc8::stimulus::emitMethodRequestAfter(iface, set);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // 3. getFieldA again — the armed getter returns 0x55 ^ 0xFF = 0xAA (!= 0x55).
        ::tc8::stimulus::MethodRequestTarget get2{};
        get2.method_id = 0x0040;
        ::tc8::stimulus::emitMethodRequestAfter(iface, get2);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts166NegSM, someip_ets_166_neg)
