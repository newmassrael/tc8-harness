#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/cases/udp_introduction_01.h"  // SSOT for kIntro01DirectedBroadcastBe
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_introduction_01_neg_sm.h"

namespace tc8::sce::cases {

using UdpIntroduction01NegSM =
    ::SCE::Generated::udp_introduction_01_neg::udp_introduction_01_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of UDP_INTRODUCTION_01: the §4.6.5.6 directed-broadcast deny is an
// application decision — lwIP delivers the directed broadcast to the INADDR_ANY data
// socket and the listener drops it on the recovered destination. The
// kAppFaultAcceptDirectedBroadcast app fault makes that listener skip the discard, so a
// buggy DUT counts the datagram the positive proves denied. lwIP-only (kCapAppFault via
// UdpAppFaultNegBase). Same app seam + directed-broadcast destination as
// ipv4_addressing_02_neg, on the §4.6.5.6 UDP case.
template <>
struct TestCaseTraits<cases::UdpIntroduction01NegSM>
    : UdpAppFaultNegBase<cases::UdpIntroduction01NegSM> {
    static constexpr std::string_view kCaseId      = "UDP_INTRODUCTION_01_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of UDP_INTRODUCTION_01: the lwIP kAppFaultAcceptDirectedBroadcast "
        "app fault makes the data listener count a directed-broadcast datagram; a "
        "conformant DUT denies it at the application layer";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitAppFlavorArm(cfg, iface, ::tc8::ut::kAppFaultAcceptDirectedBroadcast);
        ::tc8::sce::udp::emitAddressingProbeAndQuery(
            cfg, iface, cases::kIntro01DirectedBroadcastBe, cfg.dut.mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpIntroduction01NegSM, udp_introduction_01_neg)
