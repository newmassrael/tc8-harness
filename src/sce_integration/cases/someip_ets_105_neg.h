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

#include "someip_ets_105_neg_sm.h"

namespace tc8::sce::cases {

using SomeipEts105NegSM = ::SCE::Generated::someip_ets_105_neg::someip_ets_105_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §5.1.6 SOMEIP_ETS_105: GetLastValueOfEventUDPUnicast must return the
// cached event UInt8 (0x08). kEtsFaultFieldValueWrong makes the harness-owned EtsImpl getter
// return the cached value bit-flipped (0x08 ^ 0xFF = 0xF7 != 0x08), so a buggy DUT surfaces a
// last-value readback that does not match the cached event. The only faithful SOME/IP fault
// site — the response serialization is vendored-vsomeip-owned, but the cached value the getter
// returns is EtsImpl-owned. tc8-dut-only (kCapEtsFault via SomeIpEtsFaultNegBase).
template <>
struct TestCaseTraits<cases::SomeipEts105NegSM>
    : SomeIpEtsFaultNegBase<cases::SomeipEts105NegSM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_105_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of SOMEIP_ETS_105: the kEtsFaultFieldValueWrong app fault makes "
        "GetLastValueOfEventUDPUnicast return a value other than the cached 0x08; a "
        "conformant DUT returns 0x08";

    // Arm the getter value fault, then drive the same activate / subscribe / get-last chain
    // the positive uses. Only the final GetLastValueOfEventUDPUnicast readback flips.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitEtsFlavorArm(cfg, iface, ::tc8::ut::kEtsFaultFieldValueWrong);

        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SomeIpRpcMessage activate{};
        activate.method_id    = 0x002F;
        activate.message_type = ::tc8::someip::MessageType::REQUEST_NO_RETURN;
        activate.payload      = {0x00};
        ::tc8::stimulus::emitMethodRequestAfter(iface, activate, {}, ::tc8::sce::someipUdpMethodDest(cfg));
        std::this_thread::sleep_for(std::chrono::milliseconds(800));

        ::tc8::stimulus::SomeIpRpcMessage subscribe{};
        subscribe.method_id    = 0x0032;
        subscribe.message_type = ::tc8::someip::MessageType::REQUEST_NO_RETURN;
        subscribe.payload      = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        ::tc8::stimulus::emitMethodRequestAfter(iface, subscribe, {}, ::tc8::sce::someipUdpMethodDest(cfg));
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));

        // GetLastValueOfEventUDPUnicast — Method 0x3C; armed getter returns 0x08 ^ 0xFF.
        ::tc8::stimulus::SomeIpRpcMessage get_last{};
        get_last.method_id = 0x003C;
        ::tc8::stimulus::emitMethodRequestAfter(iface, get_last, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts105NegSM, someip_ets_105_neg)
