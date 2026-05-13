#pragma once

#include <string_view>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_fragments_common.h"
#include "sce_integration/ipv4_reassembly_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_reassembly_07_sm.h"

namespace tc8::sce::cases {

using Ipv4Reassembly07SM = ::SCE::Generated::ipv4_reassembly_07::ipv4_reassembly_07;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Reassembly07SM>
    : Ipv4FragmentEchoBase<cases::Ipv4Reassembly07SM> {
    static constexpr std::string_view kCaseId      = "IPv4_REASSEMBLY_07";
    static constexpr std::string_view kSpecSection = "4.4.4.7";
    static constexpr std::string_view kDescription =
        "DUT does not reassemble when an internal fragment is "
        "missing — frag (offset=0, MF=1) + frag (offset=2, MF=0) "
        "leave a hole at octets 8..15 (RFC 791 §3.2)";

    // Two IPv4 fragments at offsets 0 and 2 (8-octet units → bytes
    // 0..7 and 16..23 of the reassembled body). The middle 8 bytes
    // (offset=1, bytes 8..15) are deliberately absent; the bucket
    // never reaches full coverage and Linux's `net.ipv4.ipfrag_time`
    // (default 30 s) drops it after timeout. Frag 0 carries the
    // 8 B ICMP header so the wire frame is well-formed at the
    // packet-injection layer; frag 2 carries arbitrary 8 B filler
    // since reassembly never delivers the body to ICMP.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
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

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:              return "pass";
            case State::Fail_dut_replied:  return "fail:dut_replied_with_internal_gap";
            default:                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Reassembly07SM, ipv4_reassembly_07)
