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

#include "someip_ets_168_neg_sm.h"

namespace tc8::sce::cases {

using SomeipEts168NegSM = ::SCE::Generated::someip_ets_168_neg::someip_ets_168_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §5.1.6 SOMEIP_ETS_168: the post-set reliable-field readback is an
// application property — the EnhancedTestability service stores the set value and the getter
// echoes it over TCP. kEtsFaultFieldValueWrong makes the harness-owned EtsImpl reliable-field
// getter return the stored value bit-flipped (!= the set value), so a buggy DUT surfaces a
// readback that does not echo what was set. The only faithful SOME/IP fault site — the response
// serialization is vendored-vsomeip-owned, but the field value the getter returns is
// EtsImpl-owned. tc8-dut-only (kCapEtsFault via SomeIpEtsFaultNegBase).
template <>
struct TestCaseTraits<cases::SomeipEts168NegSM>
    : SomeIpEtsFaultNegBase<cases::SomeipEts168NegSM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_168_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of SOMEIP_ETS_168: the kEtsFaultFieldValueWrong app fault makes the "
        "reliable-field getter return a value that does not echo what setField stored; a "
        "conformant DUT echoes the set value over TCP";

    // Arm the field-getter value fault, then drive the same get / set(0x99) / get chain over
    // TCP the positive uses. The setter is untouched (its echo stays correct, so phase 3
    // mirrors the positive), and only the post-set getter readback is bit-flipped (!= 0x99).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitEtsFlavorArm(cfg, iface, ::tc8::ut::kEtsFaultFieldValueWrong);

        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        // SomeIpReliableUnicastPort per ets.fdepl = the configured services[0]
        // TCP endpoint.
        const auto tcp_dest = ::tc8::sce::someipTcpMethodDest(cfg);

        // 1. getTestFieldUint8Reliable (Method 0x2A) over TCP.
        ::tc8::stimulus::SomeIpRpcMessage get1{};
        get1.method_id = 0x002A;
        ::tc8::stimulus::emitMethodRequestTcpAfter(iface, get1,
                                                   ::tc8::stimulus::MethodRequestTiming{},
                                                   tcp_dest);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // 2. setTestFieldUint8Reliable(0x99) (Method 0x2B) over TCP. The setter echoes 0x99.
        ::tc8::stimulus::SomeIpRpcMessage set{};
        set.method_id = 0x002B;
        set.payload   = {0x99};
        ::tc8::stimulus::emitMethodRequestTcpAfter(iface, set,
                                                   ::tc8::stimulus::MethodRequestTiming{},
                                                   tcp_dest);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // 3. getTestFieldUint8Reliable again — the armed getter returns 0x99 ^ 0xFF = 0x66.
        ::tc8::stimulus::SomeIpRpcMessage get2{};
        get2.method_id = 0x002A;
        ::tc8::stimulus::emitMethodRequestTcpAfter(iface, get2,
                                                   ::tc8::stimulus::MethodRequestTiming{},
                                                   tcp_dest);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts168NegSM, someip_ets_168_neg)
