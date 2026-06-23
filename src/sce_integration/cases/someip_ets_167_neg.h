#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_167_neg_sm.h"

namespace tc8::sce::cases {

using SomeipEts167NegSM = ::SCE::Generated::someip_ets_167_neg::someip_ets_167_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §5.1.6 SOMEIP_ETS_167: the post-set array readback is an application
// property — the EnhancedTestability service stores the set array and the getter echoes it.
// kEtsFaultFieldValueWrong makes the harness-owned EtsImpl array getter (getTestFieldUint8Array)
// return the stored array with every byte complemented (!= the set array), so a buggy DUT
// surfaces a readback that does not echo what was set. The only faithful SOME/IP fault site —
// the response serialization is vendored-vsomeip-owned, but the array value the getter returns
// is EtsImpl-owned. The same flavor the scalar field _neg cases use (166/168): one flavor, all
// field getters. tc8-dut-only (kCapEtsFault via SomeIpEtsFaultNegBase).
template <>
struct TestCaseTraits<cases::SomeipEts167NegSM>
    : SomeIpEtsFaultNegBase<cases::SomeipEts167NegSM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_167_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of SOMEIP_ETS_167: the kEtsFaultFieldValueWrong app fault makes the "
        "array-field getter return an array that does not echo what setField stored; a "
        "conformant DUT echoes the set array";

    // Arm the field-getter value fault, then drive the same get / set([0x11..0x44]) / get chain
    // the positive uses. The setter is untouched (its echo stays correct, so phase 3 mirrors the
    // positive), and only the post-set getTestFieldUint8Array readback is byte-complemented
    // (first array byte 0x11 -> 0xEE).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitEtsFlavorArm(cfg, iface, ::tc8::ut::kEtsFaultFieldValueWrong);

        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        // 1. getTestFieldUint8Array (Method 0x28) — empty Request payload.
        ::tc8::stimulus::MethodRequestTarget get1{};
        get1.method_id = 0x0028;
        ::tc8::stimulus::emitMethodRequestAfter(iface, get1);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // 2. setTestFieldUint8Array (Method 0x29) — payload = 32-bit BE length (4) + 4 bytes
        // [0x11, 0x22, 0x33, 0x44]. The setter echoes the array verbatim.
        ::tc8::stimulus::MethodRequestTarget set{};
        set.method_id = 0x0029;
        set.payload   = {0x00, 0x00, 0x00, 0x04,         // length 4 (BE)
                         0x11, 0x22, 0x33, 0x44};
        ::tc8::stimulus::emitMethodRequestAfter(iface, set);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // 3. getTestFieldUint8Array again — the armed getter returns each byte ^ 0xFF, so the
        // first array byte is 0x11 ^ 0xFF = 0xEE (!= 0x11).
        ::tc8::stimulus::MethodRequestTarget get2{};
        get2.method_id = 0x0028;
        ::tc8::stimulus::emitMethodRequestAfter(iface, get2);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts167NegSM, someip_ets_167_neg)
