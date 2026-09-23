#pragma once

#include <string_view>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_fragments_common.h"
#include "sce_integration/ipv4_reassembly_common.h"
#include "sce_integration/test_runner.h"
#include "stimulus/icmpv4_builder.h"
#include "tc8/wire/icmp_echo.h"

#include "ipv4_reassembly_13_sm.h"

namespace tc8::sce::cases {

using Ipv4Reassembly13SM = ::SCE::Generated::ipv4_reassembly_13::ipv4_reassembly_13;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Reassembly13SM>
    : Ipv4FragmentEchoBase<cases::Ipv4Reassembly13SM> {
    static constexpr std::string_view kCaseId      = "IPv4_REASSEMBLY_13";
    static constexpr std::string_view kDescription =
        "DUT reassembles partially overlapping fragments using "
        "most-recent-wins (RFC 791 §3.2 Example Reassembly "
        "Procedure) and emits Echo Reply with 27 B "
        "\"ECU NETWORK VALIDATION TEST\" data";

    // Build the full 35 B Echo Request body (8 B header + 27 B
    // kReassembly13EchoPayload) so the ICMP checksum covers the
    // post-overlap-resolution reassembled region the DUT will see
    // if it follows RFC 791 §3.2's most-recent-wins semantic. Wire
    // sequence per spec:
    //   frag 0: offset=0, MF=1, payload=body[0..15] (header + first
    //           8 B of data)
    //   frag 1: offset=2, MF=1, payload=24 B
    //           kReassembly13WrongFragPayload (covers bytes 16..39
    //           of the bucket — overshoots the real total length,
    //           exercising the overlap edge case the spec calls out)
    //   frag 2: offset=2, MF=1, payload=body[16..23] (correct 8 B
    //           — partially overlaps frag 1's first 8 B with the
    //           CORRECT data; most-recent-wins should select these)
    //   frag 3: offset=3, MF=0, payload=body[24..34] (final 11 B
    //           — sets total length = 24 B + 11 B = 35 B)
    //
    // A DUT that cannot resolve the overlap and lets the bucket expire
    // says so with a Time Exceeded code 1 quoting frag 0; the SCXML
    // grades that report as an observed violation. lwIP does this.
    // Linux (post-CVE-2018-5391, kernel 4.18+) instead discards the
    // whole queue, frag 0 included, the moment frag 2 overlaps, so it
    // sends nothing and the case can only time out (inconclusive;
    // see docs/tech-debt.md TD-33).
    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        ::tc8::sce::ipv4::fragments::dispatchEchoReplyOrReassemblyExpiry<SM>(c, sm, ev);
    }

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        const auto body = ::tc8::wire::buildIcmpEchoRequestBody(
            ::tc8::stimulus::kIcmpEchoId,
            ::tc8::stimulus::kIcmpEchoSeq,
            ::tc8::sce::ipv4::reassembly::kReassembly13EchoPayload.data(),
            static_cast<std::uint32_t>(::tc8::sce::ipv4::reassembly::kReassembly13EchoPayload.size()));

        const std::vector<std::uint8_t> frag0_payload(body.begin(),       body.begin() + 16);
        const std::vector<std::uint8_t> frag1_payload(
            ::tc8::sce::ipv4::reassembly::kReassembly13WrongFragPayload.begin(),
            ::tc8::sce::ipv4::reassembly::kReassembly13WrongFragPayload.end());
        const std::vector<std::uint8_t> frag2_payload(body.begin() + 16, body.begin() + 24);
        const std::vector<std::uint8_t> frag3_payload(body.begin() + 24, body.end());

        const auto ip_id = ::tc8::sce::ipv4::reassembly::kReassembly13IpId;

        ::tc8::sce::ipv4::reassembly::emitIpv4Fragment(
            iface, cfg, cfg.arp.dut_iface_mac, ip_id,
            /*offset=*/0, /*MF=*/true, /*ttl=*/64, frag0_payload);
        ::tc8::sce::ipv4::reassembly::emitIpv4Fragment(
            iface, cfg, cfg.arp.dut_iface_mac, ip_id,
            /*offset=*/2, /*MF=*/true, /*ttl=*/64, frag1_payload);
        ::tc8::sce::ipv4::reassembly::emitIpv4Fragment(
            iface, cfg, cfg.arp.dut_iface_mac, ip_id,
            /*offset=*/2, /*MF=*/true, /*ttl=*/64, frag2_payload);
        ::tc8::sce::ipv4::reassembly::emitIpv4Fragment(
            iface, cfg, cfg.arp.dut_iface_mac, ip_id,
            /*offset=*/3, /*MF=*/false, /*ttl=*/64, frag3_payload);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Reassembly13SM, ipv4_reassembly_13)
