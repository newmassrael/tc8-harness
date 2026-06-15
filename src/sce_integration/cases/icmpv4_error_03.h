#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "icmpv4_error_03_sm.h"

namespace tc8::sce::cases {

using Icmpv4Error03SM = ::SCE::Generated::icmpv4_error_03::icmpv4_error_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Icmpv4Error03SM>
    : Icmpv4TypedBase<cases::Icmpv4Error03SM, std::uint8_t{12}> {
    static constexpr std::string_view kCaseId      = "ICMPv4_ERROR_03";
    static constexpr std::string_view kSpecSection = "4.3.3.1";
    static constexpr std::string_view kDescription =
        "DUT must not emit ICMP Parameter Problem for a malformed "
        "Internet Timestamp option carried on a fragment with "
        "offset != 0 (RFC 791 §3.1 options parse only on fragment 0)";

    // Send a 2-fragment stimulus. Each fragment is a standalone IP
    // packet (separate Eth header + IP header) so we issue two
    // `emitStimulus` calls rather than growing the builder into a
    // fragmenter — the per-fragment option bytes differ (length=12
    // on frag 0 vs length=10 on frag 1), and conceptually each
    // fragment is its own IP datagram from the wire's perspective.
    //
    // Fragment geometry: the "constructed ICMP packet" is 16 B total
    // (`kIcmpv4FragmentStimulusPacket`), split into two 8 B halves
    // for clean 8-octet fragment alignment. Frag 0 carries the
    // notional ICMP header region as a raw 8 B payload (no ICMP
    // header synthesis — the bytes ARE what the wire needs); frag 1
    // carries the notional payload region. The DUT's options parser
    // runs on frag 0 (valid length-12 option → no Parameter Problem)
    // and skips frag 1 (malformed length-10 option, but offset != 0
    // disqualifies the parse).
    //
    // L2 destination is DUT-unicast to keep the PACKET_HOST gate
    // posture symmetric with ERROR_02 — any spurious Parameter
    // Problem emission here would be attributable to the
    // fragment-zero-vs-nonzero distinction, not to an L2 kernel-
    // gate difference.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        // Frag 0 — MF=1, offset=0, length-12 Timestamp option
        // (well-formed under flag=0 mode: 4 B header + one filled
        // 4 B slot + one free 4 B slot). 8 B raw IP payload = first
        // half of `kIcmpv4FragmentStimulusPacket`.
        ::tc8::sce::icmpv4::StimulusOverrides f0{};
        f0.dst_mac         = cfg.arp.dut_iface_mac;
        f0.more_fragments  = true;
        f0.fragment_offset = 0;
        f0.ip_options.assign(::tc8::stimulus::kIcmpv4TimestampOptionLen12.begin(),
                             ::tc8::stimulus::kIcmpv4TimestampOptionLen12.end());
        f0.raw_ip_payload.assign(
            ::tc8::stimulus::kIcmpv4FragmentStimulusPacket.begin(),
            ::tc8::stimulus::kIcmpv4FragmentStimulusPacket.begin() + 8);
        ::tc8::sce::icmpv4::emitStimulus(cfg, iface, f0);

        // Frag 1 — MF=0, offset = first-fragment data size in 8-
        // octet units = 8 / 8 = 1. Malformed length-10 Timestamp
        // option (same defect as ERROR_02's frag 0, but here on a
        // non-zero-offset fragment so the DUT's options parser
        // skips it). 8 B raw IP payload = second half of
        // `kIcmpv4FragmentStimulusPacket`.
        ::tc8::sce::icmpv4::StimulusOverrides f1{};
        f1.dst_mac         = cfg.arp.dut_iface_mac;
        f1.more_fragments  = false;
        f1.fragment_offset = 1;
        f1.ip_options.assign(::tc8::stimulus::kIcmpv4TimestampOptionMalformed.begin(),
                             ::tc8::stimulus::kIcmpv4TimestampOptionMalformed.end());
        f1.raw_ip_payload.assign(
            ::tc8::stimulus::kIcmpv4FragmentStimulusPacket.begin() + 8,
            ::tc8::stimulus::kIcmpv4FragmentStimulusPacket.end());
        ::tc8::sce::icmpv4::emitStimulus(cfg, iface, f1);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Icmpv4Error03SM, icmpv4_error_03)
