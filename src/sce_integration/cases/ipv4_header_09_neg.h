#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/ipv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_header_09_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4Header09NegSM = ::SCE::Generated::ipv4_header_09_neg::ipv4_header_09_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.4.4.1 IPv4_HEADER_09: a conformant DUT silently discards an IPv4 datagram
// whose Total Length field (48) exceeds the actual transmitted L3 payload, emitting no reply.
// kIcmpFaultSynthEchoReply makes the lwIP netif INPUT hook synthesize the prohibited Echo Reply
// when the oversized-Total-Length Echo Request arrives — the hook reads the trigger at fixed
// offsets and builds a fresh, well-formed Echo Reply, so the inconsistent length never reaches
// lwIP's own length validation and the synthesized reply is the only DUT-origin frame. The case
// passes only when that reply is observed. lwIP-only (kCapIngressFault). The ingress-synthesis
// seam reaches this IPv4-layer must-not-reply guard — no DUT-emitted frame for the egress
// field-fault to corrupt. ReplyType 0 (Echo Reply) narrows the observed variant.
template <>
struct TestCaseTraits<cases::Ipv4Header09NegSM>
    : Icmpv4IngressFaultNegBase<cases::Ipv4Header09NegSM, std::uint8_t{0}> {
    static constexpr std::string_view kCaseId      = "IPv4_HEADER_09_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of IPv4_HEADER_09: the lwIP kIcmpFaultSynthEchoReply ingress flavor "
        "makes the DUT reply to an oversized-Total-Length Echo Request; a conformant DUT discards "
        "it and stays silent";

    // Arm the Echo-Reply synthesis fault, then send the same oversized-Total-Length Echo Request
    // the positive uses (the datagram the DUT must drop without replying).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kIcmpFaultSynthEchoReply);
        ::tc8::sce::ipv4::StimulusOverrides ov{};
        ov.total_length = std::uint16_t{48};  // > actual L3 payload (28 B on wire)
        ::tc8::sce::ipv4::emitStimulus(cfg, iface, ov);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Header09NegSM, ipv4_header_09_neg)
