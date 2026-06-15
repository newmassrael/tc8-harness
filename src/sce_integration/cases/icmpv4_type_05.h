#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "icmpv4_type_05_sm.h"

namespace tc8::sce::cases {

using Icmpv4Type05SM = ::SCE::Generated::icmpv4_type_05::icmpv4_type_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Icmpv4Type05SM>
    : Icmpv4TypedBase<cases::Icmpv4Type05SM, std::uint8_t{0}> {
    static constexpr std::string_view kCaseId      = "ICMPv4_TYPE_05";
    static constexpr std::string_view kSpecSection = "4.3.3.2";
    static constexpr std::string_view kDescription =
        "DUT discards an ICMP Echo Request with an IP header parameter "
        "problem (malformed Internet Timestamp option) and must not "
        "emit an Echo Reply (RFC 792 Parameter Problem MUST)";

    // Send an ICMP Echo Request whose IPv4 header carries a malformed
    // Internet Timestamp option — the option's `length` byte claims
    // 10 while only 8 B of option data appear on the wire, and the
    // `pointer` byte (9) points past `length + 1` per RFC 791 §3.1.
    // A conformant DUT rejects at IP-options parsing per RFC 792
    // "Parameter Problem" and MUST NOT emit an Echo Reply.
    //
    // Option bytes are single-sourced as `kIcmpv4TimestampOptionMalformed`
    // in `stimulus/icmpv4_builder.h`. The builder inserts them between
    // the fixed IPv4 header and the ICMP body, bumps IHL to 7, and
    // recomputes total_length + checksum so the frame is internally
    // consistent — the DUT's drop reason is the options malformation,
    // not a checksum or length artefact masking it.
    //
    // L2 destination is the DUT's real MAC (cfg.arp.dut_iface_mac)
    // rather than the builder's Ethernet-broadcast default. Linux's
    // Echo Reply path does not gate on pkt_type (see
    // `reference_icmp_packet_host_gate.md`), so broadcast would still
    // elicit a reply on a conformant DUT — but unicast keeps the
    // observable behaviour attributable to the option malformation
    // alone. Cross-protocol reach on `arp.*` is consistent with
    // TYPE_18.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::icmpv4::StimulusOverrides ov{};
        ov.dst_mac = cfg.arp.dut_iface_mac;
        ov.ip_options.assign(::tc8::stimulus::kIcmpv4TimestampOptionMalformed.begin(),
                             ::tc8::stimulus::kIcmpv4TimestampOptionMalformed.end());
        ::tc8::sce::icmpv4::emitStimulus(cfg, iface, ov);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Icmpv4Type05SM, icmpv4_type_05)
