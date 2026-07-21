#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/cases/ipv4_header_08.h"  // SSOT for kIpv4Header08BadIhl
#include "sce_integration/ipv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_header_08_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4Header08NegSM = ::SCE::Generated::ipv4_header_08_neg::ipv4_header_08_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.4.4.1 IPv4_HEADER_08: a conformant DUT silently discards an IPv4 datagram
// whose IHL*4 exceeds its Total Length (the spec literal IHL=13 with the default tot_len=28 implies
// a 52-byte header inside a 28-byte datagram), emitting no reply. kIcmpFaultSynthEchoReply makes the
// lwIP netif INPUT hook synthesize the prohibited Echo Reply when the malformed-IHL Echo Request
// arrives, and the case passes only when that DUT-origin reply is observed. The netif hook reads the
// protocol byte at its fixed IPv4-header offset (still ICMP) before ip4_input's length validation, so
// the bad-IHL trigger does not block the synthesis; the observed Echo Reply itself is well-formed.
// lwIP-only (kCapIngressFault). The ingress-synthesis seam reaches this IPv4-layer must-not-reply
// guard — no DUT-emitted frame for an egress field-fault to corrupt. ReplyType 0 (Echo Reply)
// narrows the observed variant.
template <>
struct TestCaseTraits<cases::Ipv4Header08NegSM>
    : Icmpv4IngressFaultNegBase<cases::Ipv4Header08NegSM, std::uint8_t{0}> {
    static constexpr std::string_view kCaseId      = "IPv4_HEADER_08_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of IPv4_HEADER_08: the lwIP kIcmpFaultSynthEchoReply ingress flavor "
        "makes the DUT reply to an IHL*4 > Total Length Echo Request; a conformant DUT discards "
        "it and stays silent";

    // Arm the Echo-Reply synthesis fault, then send the same malformed-IHL Echo Request the
    // positive uses (the datagram the DUT must drop without replying).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kIcmpFaultSynthEchoReply);
        ::tc8::sce::ipv4::StimulusOverrides ov{};
        ov.ihl = cases::kIpv4Header08BadIhl;
        ::tc8::sce::ipv4::emitStimulus(cfg, iface, ov);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Header08NegSM, ipv4_header_08_neg)
