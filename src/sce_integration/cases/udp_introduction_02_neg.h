#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/cases/udp_introduction_02.h"  // SSOT for kAllSystemsMcastBe
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_introduction_02_neg_sm.h"

namespace tc8::sce::cases {

using UdpIntroduction02NegSM =
    ::SCE::Generated::udp_introduction_02_neg::udp_introduction_02_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of UDP_INTRODUCTION_02: the §4.6.5.6 multicast deny is an application
// decision — lwIP delivers the all-systems multicast to the INADDR_ANY data socket and
// the listener drops it on the recovered destination. The kAppFaultAcceptMulticast app
// fault makes that listener skip the deny, so a buggy DUT counts the datagram the
// positive proves denied. lwIP-only (kCapAppFault via UdpAppFaultNegBase). Sibling of
// ipv4_addressing_02_neg on the UDP dispatch — same app seam, multicast destination.
template <>
struct TestCaseTraits<cases::UdpIntroduction02NegSM>
    : UdpAppFaultNegBase<cases::UdpIntroduction02NegSM> {
    static constexpr std::string_view kCaseId      = "UDP_INTRODUCTION_02_NEG";
    static constexpr std::string_view kSpecSection = "4.6.5.6";
    static constexpr std::string_view kDescription =
        "Self-validation of UDP_INTRODUCTION_02: the lwIP kAppFaultAcceptMulticast app "
        "fault makes the data listener count an all-systems multicast datagram; a "
        "conformant DUT denies it at the application layer";

    // Arm the app-layer acceptance fault, then drive the same all-systems multicast
    // probe + UT GetReceivedUdp query the positive uses (the multicast destination is
    // the only wire-level shape; the SCXML's {$expected_received}=1 flip and the armed
    // flavor make it a negative). With the flavor armed the data listener skips its
    // multicast deny so ut_received == 1.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitAppFlavorArm(cfg, iface, ::tc8::ut::kAppFaultAcceptMulticast);
        ::tc8::sce::udp::emitAddressingProbeAndQuery(
            cfg, iface, cases::kAllSystemsMcastBe, cfg.dut.mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpIntroduction02NegSM, udp_introduction_02_neg)
