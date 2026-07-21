#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "icmpv4_error_02_sm.h"

namespace tc8::sce::cases {

using Icmpv4Error02SM = ::SCE::Generated::icmpv4_error_02::icmpv4_error_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Icmpv4Error02SM>
    : Icmpv4TypedBase<cases::Icmpv4Error02SM, std::uint8_t{12}> {
    static constexpr std::string_view kCaseId      = "ICMPv4_ERROR_02";
    static constexpr std::string_view kDescription =
        "DUT emits ICMP Parameter Problem (type=12) on receiving "
        "fragment 0 (MF=1, offset=0) carrying a malformed Internet "
        "Timestamp option; Pointer identifies the malformed byte "
        "(RFC 792 Parameter Problem MUST)";

    // Send fragment 0 (MF=1, offset=0) of a hypothetical 2-fragment
    // Echo Request carrying the malformed length-10 Internet
    // Timestamp option. The spec describes "first half of the
    // constructed ICMP packet" — with payload_len=0 the full ICMP
    // packet is the 8 B header, and the single fragment naturally
    // carries those 8 bytes (a multiple of the IP 8-octet fragment
    // unit). The DUT's IP-layer options parser runs on fragment 0
    // regardless of whether fragment 1 ever arrives; the malformed
    // length/pointer triggers Parameter Problem per RFC 792.
    //
    // Option bytes and the IHL=7 geometry are single-sourced as
    // `kIcmpv4TimestampOptionMalformed` — same literal as TYPE_05 /
    // ERROR_04, keeping the "malformed options" invariant in one
    // place.
    //
    // L2 destination must be DUT-unicast: Linux's `icmp_send` gates
    // error-class ICMP on `skb->pkt_type == PACKET_HOST`, so the
    // Eth-broadcast default silently suppresses the Parameter
    // Problem emission. Same reach as TYPE_18 / TYPE_05 — the DUT
    // MAC is an L2 identity threaded via `cfg.arp.dut_iface_mac`.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::icmpv4::StimulusOverrides ov{};
        ov.dst_mac        = cfg.arp.dut_iface_mac;
        ov.more_fragments = true;
        ov.fragment_offset = 0;
        ov.ip_options.assign(::tc8::stimulus::kIcmpv4TimestampOptionMalformed.begin(),
                             ::tc8::stimulus::kIcmpv4TimestampOptionMalformed.end());
        ::tc8::sce::icmpv4::emitStimulus(cfg, iface, ov);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Icmpv4Error02SM, icmpv4_error_02)
