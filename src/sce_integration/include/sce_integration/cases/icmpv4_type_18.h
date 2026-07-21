#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "icmpv4_type_18_sm.h"

namespace tc8::sce::cases {

using Icmpv4Type18SM = ::SCE::Generated::icmpv4_type_18::icmpv4_type_18;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Icmpv4Type18SM>
    : Icmpv4TypedBase<cases::Icmpv4Type18SM, std::uint8_t{3}> {
    static constexpr std::string_view kCaseId      = "ICMPv4_TYPE_18";
    static constexpr std::string_view kDescription =
        "DUT emits ICMP Destination Unreachable / Protocol Unreachable "
        "(type=3, code=2) on receiving an IPv4 packet with an "
        "unsupported Protocol (RFC 1122 §3.2.2.1 MUST)";

    // Send an IPv4 packet whose Protocol byte is 253 — RFC 3692 reserves
    // 253/254 "for experimentation and testing," so no conformant host
    // has an L4 handler for it. Linux drops at ip_local_deliver_finish
    // when inet_protos[253] is NULL and calls icmp_send(DEST_UNREACH,
    // PROT_UNREACH, ...) per RFC 1122.
    //
    // L2 destination must be DUT-unicast: `icmp_send` in
    // net/ipv4/icmp.c gates Destination Unreachable emission on
    // `skb->pkt_type == PACKET_HOST`, so the Eth-broadcast default
    // (which works for Echo Request via a separate icmp_echo path)
    // silently suppresses the reply for error-class ICMP. We read
    // the DUT MAC from `cfg.arp.dut_iface_mac` rather than duplicate
    // the field under `icmpv4.*`: the MAC is an L2 identity, not an
    // ARP-specific expectation, and smoke-test.sh already plumbs it
    // via `--expect arp.dut_iface_mac=...`. When a second ICMP case
    // needs unicast stimulus, promote the field or keep the reach.
    //
    // The builder still emits an ICMP-shaped body behind the IPv4
    // header because that's its only production mode; the DUT drops
    // before any L4 parsing, so body contents are ignored. Future
    // raw-IPv4 cases (e.g. §4.4.4.5 UDP-stimulus ADDRESSING_01/_02)
    // may motivate a dedicated ipv4_raw builder, but for TYPE_18
    // alone the override is cheaper than a new builder.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::icmpv4::StimulusOverrides ov{};
        ov.ip_protocol = std::uint8_t{253};  // RFC 3692 experimental
        ov.dst_mac     = cfg.arp.dut_iface_mac;
        ::tc8::sce::icmpv4::emitStimulus(cfg, iface, ov);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Icmpv4Type18SM, icmpv4_type_18)
