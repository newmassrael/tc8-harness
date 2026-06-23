#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/ipv4_fragments_common.h"
#include "sce_integration/ipv4_reassembly_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_reassembly_09_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4Reassembly09NegSM = ::SCE::Generated::ipv4_reassembly_09_neg::ipv4_reassembly_09_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.4.4.7 IPv4_REASSEMBLY_09: a conformant DUT never completes a single
// fragment that carries the full 16 B Echo Request body at offset=0 but advertises MF=1 (more
// fragments promised, none arriving), so the reassembly bucket times out and the DUT stays
// silent. kIcmpFaultSynthEchoReply makes the lwIP netif INPUT hook synthesize the prohibited
// Echo Reply as the fragment arrives. The hook gates on the IPv4 ethertype and the protocol
// byte at its fixed offset (still ICMP), not on the MF bit, and the reply builder reads only
// fixed trigger fields (eth/IP source), so the never-completing bucket does not block the
// synthesis; the synthesized reply is well-formed and DUT-origin. The case passes only when
// that reply is observed. lwIP-only (kCapIngressFault). The ingress-synthesis seam reaches
// this IPv4 reassembly must-not-reply guard — the prohibited emission is a reassembly-derived
// Echo Reply, not a corruptible DUT-emitted frame. ReplyType 0 (Echo Reply) narrows the
// observed variant.
template <>
struct TestCaseTraits<cases::Ipv4Reassembly09NegSM>
    : Icmpv4IngressFaultNegBase<cases::Ipv4Reassembly09NegSM, std::uint8_t{0}> {
    static constexpr std::string_view kCaseId      = "IPv4_REASSEMBLY_09_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of IPv4_REASSEMBLY_09: the lwIP kIcmpFaultSynthEchoReply ingress "
        "flavor makes the DUT reply to a lone MF=1 fragment; a conformant DUT holds the "
        "never-completing bucket and stays silent";

    // Arm the Echo-Reply synthesis fault, then send the same single MF=1 fragment the
    // positive uses (offset=0 carrying the full 16 B Echo Request body, no following
    // fragment). The synthesis fires on the fragment's arrival, well inside the
    // icmpv4_synth_neg listen window.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kIcmpFaultSynthEchoReply);

        const auto body = ::tc8::sce::ipv4::reassembly::buildReassembly16BEchoBody();
        ::tc8::sce::ipv4::reassembly::emitIpv4Fragment(
            iface, cfg, cfg.arp.dut_iface_mac,
            ::tc8::sce::ipv4::reassembly::kReassembly09IpId,
            /*fragment_offset=*/0,
            /*more_fragments=*/true,
            /*ttl=*/64,
            body);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Reassembly09NegSM, ipv4_reassembly_09_neg)
