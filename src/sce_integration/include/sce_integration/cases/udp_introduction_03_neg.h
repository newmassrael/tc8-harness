#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/cases/udp_introduction_03.h"  // SSOT for kIntro03UnusedDstPort / kIntro03Probe
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_introduction_03_neg_sm.h"

namespace tc8::sce::cases {

using UdpIntroduction03NegSM = ::SCE::Generated::udp_introduction_03_neg::udp_introduction_03_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.6.5.6 UDP_INTRODUCTION_03: a conformant DUT answers a UDP datagram sent to
// a port with no pending LISTEN with an ICMP Destination Unreachable / Port Unreachable (type 3
// code 3, RFC 1122 §4.1.3.1). kIcmpFaultDestUnreachCodeWrong makes the lwIP link-output hook
// XOR-flip the code of that reply (gated on type 3, type left intact), and the case passes only
// when the corrupted code (!= 3) is observed. lwIP-only (kCapEgressFault via
// Icmpv4EgressFaultNegBase). The sibling of ICMPv4_TYPE_18_NEG — the UDP-elicited
// Destination Unreachable instead of the protocol-unreachable one. ReplyType 3 narrows the
// observed variant to Destination Unreachable.
template <>
struct TestCaseTraits<cases::UdpIntroduction03NegSM>
    : Icmpv4EgressFaultNegBase<cases::UdpIntroduction03NegSM, std::uint8_t{3}> {
    static constexpr std::string_view kCaseId      = "UDP_INTRODUCTION_03_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of UDP_INTRODUCTION_03: the lwIP kIcmpFaultDestUnreachCodeWrong egress "
        "flavor flips the DUT's Port Unreachable code off 3; a conformant DUT emits code 3";

    // Arm the dest-unreach code-flip, then send the same UDP probe to the unused port the
    // positive uses (the datagram that draws the DUT's Port Unreachable). The Eth dst override
    // keeps Linux's ICMP error path on the PACKET_HOST gate; harmless on lwIP.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kIcmpFaultDestUnreachCodeWrong);
        ::tc8::sce::udp::UdpStimulusOverrides ov{};
        ov.eth_dst_override = cfg.dut.mac;
        ::tc8::sce::udp::emitUdpStimulus(
            cfg, iface,
            cfg.ipv4.dut_iface_ip,
            ::tc8::sce::udp::kDataPeerPort,
            cases::kIntro03UnusedDstPort,
            cases::kIntro03Probe.data(),
            cases::kIntro03Probe.size(),
            ::tc8::sce::udp::kUdpPilotInitialWait,
            ov);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpIntroduction03NegSM, udp_introduction_03_neg)
