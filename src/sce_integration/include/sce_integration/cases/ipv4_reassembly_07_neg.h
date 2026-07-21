#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/ipv4_fragments_common.h"
#include "sce_integration/ipv4_reassembly_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_reassembly_07_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4Reassembly07NegSM = ::SCE::Generated::ipv4_reassembly_07_neg::ipv4_reassembly_07_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.4.4.7 IPv4_REASSEMBLY_07: a conformant DUT never reassembles a
// fragment bucket with an internal hole (octets 8..15 missing between offset=0 and offset=2),
// so it delivers nothing to ICMP and emits no Echo Reply. kIcmpFaultSynthEchoReply makes the
// lwIP netif INPUT hook synthesize the prohibited Echo Reply as the first fragment arrives.
// The hook gates on the IPv4 ethertype and the protocol byte at its fixed offset (still ICMP
// in every fragment), not on the reassembly outcome, and the reply builder reads only fixed
// trigger fields (eth/IP source), so the internal gap does not block the synthesis; the
// synthesized reply is well-formed and DUT-origin. The case passes only when that reply is
// observed. lwIP-only (kCapIngressFault). The ingress-synthesis seam reaches this IPv4
// reassembly must-not-reply guard — the prohibited emission is a reassembly-derived Echo
// Reply, not a corruptible DUT-emitted frame. ReplyType 0 (Echo Reply) narrows the observed
// variant.
template <>
struct TestCaseTraits<cases::Ipv4Reassembly07NegSM>
    : Icmpv4IngressFaultNegBase<cases::Ipv4Reassembly07NegSM, std::uint8_t{0}> {
    static constexpr std::string_view kCaseId      = "IPv4_REASSEMBLY_07_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of IPv4_REASSEMBLY_07: the lwIP kIcmpFaultSynthEchoReply ingress "
        "flavor makes the DUT reply to a fragment bucket with an internal hole; a conformant "
        "DUT never reassembles it and stays silent";

    // Arm the Echo-Reply synthesis fault, then send the same two fragments the positive uses
    // (offset=0 MF=1 carrying the 8 B ICMP header, offset=2 MF=0 filler — octets 8..15
    // absent). The synthesis fires on the first fragment's arrival, well inside the
    // icmpv4_synth_neg listen window.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kIcmpFaultSynthEchoReply);

        const auto body = ::tc8::sce::ipv4::reassembly::buildReassembly16BEchoBody();
        const std::vector<std::uint8_t> frag0_payload(body.begin(), body.begin() + 8);
        const std::vector<std::uint8_t> frag2_payload(8, 0xCC);

        ::tc8::sce::ipv4::reassembly::emitIpv4Fragment(
            iface, cfg, cfg.arp.dut_iface_mac,
            ::tc8::sce::ipv4::reassembly::kReassembly07IpId,
            /*fragment_offset=*/0,
            /*more_fragments=*/true,
            /*ttl=*/64,
            frag0_payload);

        ::tc8::sce::ipv4::reassembly::emitIpv4Fragment(
            iface, cfg, cfg.arp.dut_iface_mac,
            ::tc8::sce::ipv4::reassembly::kReassembly07IpId,
            /*fragment_offset=*/2,
            /*more_fragments=*/false,
            /*ttl=*/64,
            frag2_payload);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Reassembly07NegSM, ipv4_reassembly_07_neg)
