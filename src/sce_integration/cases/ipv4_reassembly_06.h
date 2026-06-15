#pragma once

#include <string_view>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_fragments_common.h"
#include "sce_integration/ipv4_reassembly_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_reassembly_06_sm.h"

namespace tc8::sce::cases {

using Ipv4Reassembly06SM = ::SCE::Generated::ipv4_reassembly_06::ipv4_reassembly_06;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Reassembly06SM>
    : Ipv4FragmentEchoBase<cases::Ipv4Reassembly06SM> {
    static constexpr std::string_view kCaseId      = "IPv4_REASSEMBLY_06";
    static constexpr std::string_view kSpecSection = "4.4.4.7";
    static constexpr std::string_view kDescription =
        "DUT does not reassemble when offset=0 fragment is missing — "
        "frag (offset=1, MF=1) + frag (offset=2, MF=0) leave a hole "
        "at octets 0..7 (RFC 791 §3.2)";

    // Two IPv4 fragments at offsets 1 and 2 (8-octet units = 8 and 16
    // bytes into the reassembled body). The bucket carries 16 B of
    // payload covering body octets 8..23 but no octet=0 head. The
    // wire payloads are arbitrary 8 B fillers — a conformant DUT
    // never reassembles this bucket, so the body content (and ICMP
    // checksum) are irrelevant on the wire side. The case-level
    // assertion is purely structural: tuple-keyed bucket with no
    // offset=0 fragment cannot be delivered to upper layer.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        const std::vector<std::uint8_t> frag_payload_a(8, 0xAA);
        const std::vector<std::uint8_t> frag_payload_b(8, 0xBB);

        ::tc8::sce::ipv4::reassembly::emitIpv4Fragment(
            iface, cfg, cfg.arp.dut_iface_mac,
            ::tc8::sce::ipv4::reassembly::kReassembly06IpId,
            /*fragment_offset=*/1,
            /*more_fragments=*/true,
            /*ttl=*/64,
            frag_payload_a);

        ::tc8::sce::ipv4::reassembly::emitIpv4Fragment(
            iface, cfg, cfg.arp.dut_iface_mac,
            ::tc8::sce::ipv4::reassembly::kReassembly06IpId,
            /*fragment_offset=*/2,
            /*more_fragments=*/false,
            /*ttl=*/64,
            frag_payload_b);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Reassembly06SM, ipv4_reassembly_06)
