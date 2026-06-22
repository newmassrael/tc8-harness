#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/cases/ipv4_addressing_02.h"  // SSOT for kDirectedBroadcastBe
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "ipv4_addressing_02_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4Addressing02NegSM =
    ::SCE::Generated::ipv4_addressing_02_neg::ipv4_addressing_02_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.4.4.5 IPv4_ADDRESSING_02: the directed-broadcast discard is an
// application decision (RFC 1122) — lwIP delivers the directed broadcast to the
// INADDR_ANY data-listener socket and the listener drops it on the recovered
// destination. kAppFaultAcceptDirectedBroadcast makes the listener skip the discard, so
// a buggy DUT counts the datagram the positive proves dropped. lwIP-only (kCapAppFault
// via UdpAppFaultNegBase — the observation is a UDP UT confirmation, so it shares the UDP
// dispatch base despite sitting in the IPv4 addressing section). Sibling of udp_introduction_02_neg.
template <>
struct TestCaseTraits<cases::Ipv4Addressing02NegSM>
    : UdpAppFaultNegBase<cases::Ipv4Addressing02NegSM> {
    static constexpr std::string_view kCaseId       = "IPv4_ADDRESSING_02_NEG";
    static constexpr std::string_view kSpecSection  = "4.4.4.5";
    static constexpr std::string_view kDescription  =
        "Self-validation of IPv4_ADDRESSING_02: the lwIP kAppFaultAcceptDirectedBroadcast "
        "app fault makes the data listener count a directed-broadcast datagram; a "
        "conformant DUT discards it at the application layer";

    // Arm the app-layer acceptance fault, then drive the same directed-broadcast probe +
    // UT GetReceivedUdp query the positive uses; the SCXML's expected_received=1 flip and
    // the armed flavor are what make it a negative. With the flavor armed the data
    // listener skips its discard so ut_received == 1.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitAppFlavorArm(cfg, iface, ::tc8::ut::kAppFaultAcceptDirectedBroadcast);
        ::tc8::sce::udp::emitAddressingProbeAndQuery(
            cfg, iface, cases::kDirectedBroadcastBe, cfg.dut.mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Addressing02NegSM, ipv4_addressing_02_neg)
