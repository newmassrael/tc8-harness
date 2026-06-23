#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/cases/ipv4_addressing_01.h"  // SSOT for kLimitedBroadcastBe
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "ipv4_addressing_01_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4Addressing01NegSM =
    ::SCE::Generated::ipv4_addressing_01_neg::ipv4_addressing_01_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.4.4.5 IPv4_ADDRESSING_01: the lwIP kUdpFaultRejectValid ingress
// flavor makes the input hook swallow the inbound limited-broadcast datagram (never
// forwards it to lwIP), so the receive-counting app never sees one the DUT must receive;
// a conformant DUT still receives it (ut_received == 1, the fault-inert branch). lwIP-only
// (kCapIngressFault via UdpIngressFaultNegBase — the observation is a UDP UT confirmation,
// so it shares the UDP dispatch base despite sitting in the IPv4 addressing section).
template <>
struct TestCaseTraits<cases::Ipv4Addressing01NegSM>
    : UdpIngressFaultNegBase<cases::Ipv4Addressing01NegSM> {
    static constexpr std::string_view kCaseId       = "IPv4_ADDRESSING_01_NEG";
    static constexpr std::string_view kDescription  =
        "Self-validation of IPv4_ADDRESSING_01: the lwIP kUdpFaultRejectValid ingress "
        "flavor makes the DUT drop a limited-broadcast datagram; a conformant DUT receives it";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kUdpFaultRejectValid);
        ::tc8::sce::udp::emitAddressingProbeAndQuery(
            cfg, iface, cases::kLimitedBroadcastBe, cfg.dut.mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Addressing01NegSM, ipv4_addressing_01_neg)
