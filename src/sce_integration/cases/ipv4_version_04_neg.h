#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/cases/ipv4_version_04.h"  // SSOT for kIpv4Version04BadVersion
#include "sce_integration/ipv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_version_04_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4Version04NegSM = ::SCE::Generated::ipv4_version_04_neg::ipv4_version_04_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.4.4.4 IPv4_VERSION_04: a conformant DUT silently discards an IPv4 datagram
// whose Version field is not 4 (the trigger sets it to 6), emitting no reply. kIcmpFaultSynthEchoReply
// makes the lwIP netif INPUT hook synthesize the prohibited Echo Reply when the wrong-version Echo
// Request arrives, and the case passes only when that DUT-origin reply is observed. The hook gates on
// the L2 ethertype (0x0800) and the protocol byte at its fixed IPv4-header offset (still ICMP) — NOT
// the IP Version field — and runs before ip4_input's version drop, so the wrong-version trigger does
// not block the synthesis; the synthesized reply itself carries Version 4. lwIP-only
// (kCapIngressFault). The ingress-synthesis seam reaches this IPv4-layer must-not-reply guard — no
// DUT-emitted frame for an egress field-fault to corrupt. ReplyType 0 (Echo Reply) narrows the
// observed variant.
template <>
struct TestCaseTraits<cases::Ipv4Version04NegSM>
    : Icmpv4IngressFaultNegBase<cases::Ipv4Version04NegSM, std::uint8_t{0}> {
    static constexpr std::string_view kCaseId      = "IPv4_VERSION_04_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of IPv4_VERSION_04: the lwIP kIcmpFaultSynthEchoReply ingress flavor "
        "makes the DUT reply to a Version!=4 Echo Request; a conformant DUT discards it and "
        "stays silent";

    // Arm the Echo-Reply synthesis fault, then send the same wrong-version Echo Request the
    // positive uses (the datagram the DUT must drop without replying).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kIcmpFaultSynthEchoReply);
        ::tc8::sce::ipv4::StimulusOverrides ov{};
        ov.version = cases::kIpv4Version04BadVersion;
        ::tc8::sce::ipv4::emitStimulus(cfg, iface, ov);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Version04NegSM, ipv4_version_04_neg)
