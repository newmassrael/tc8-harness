#pragma once

#include <string_view>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_fragments_common.h"
#include "sce_integration/ipv4_reassembly_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_reassembly_04_sm.h"

namespace tc8::sce::cases {

using Ipv4Reassembly04SM = ::SCE::Generated::ipv4_reassembly_04::ipv4_reassembly_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Reassembly04SM>
    : Ipv4FragmentEchoBase<cases::Ipv4Reassembly04SM> {
    static constexpr std::string_view kCaseId      = "IPv4_REASSEMBLY_04";
    static constexpr std::string_view kSpecSection = "4.4.4.7";
    static constexpr std::string_view kDescription =
        "DUT reassembles a 4-fragment Echo Request received out of "
        "order (frag 0, frag 2, frag 1, frag 3) and emits an Echo "
        "Reply with matching id/seq/data (RFC 791 §3.2)";

    // Build the full 32 B Echo Request body once (8 B ICMP header +
    // 24 B kReassembly04EchoPayload) so the ICMP checksum covers
    // the reassembled region the DUT will see. Slice into 4 chunks
    // of 8 B at offsets 0..3 (8-octet units). Wire emit order:
    // frag 0, frag 2, frag 1, frag 3 — out-of-order arrival proves
    // the DUT reassembles by offset key, not arrival order.
    //
    // All 4 fragments share the same (src_ip, dst_ip, ip_id,
    // protocol) tuple so they land in a single reassembly bucket;
    // frag 3's MF=0 closes the bucket, all 32 B coverage achieved,
    // ICMP delivers the reassembled Echo Request → Echo Reply.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        const auto body = ::tc8::sce::ipv4::reassembly::buildReassembly32BEchoBody();
        const std::vector<std::uint8_t> frag0_payload(body.begin() +  0, body.begin() +  8);
        const std::vector<std::uint8_t> frag1_payload(body.begin() +  8, body.begin() + 16);
        const std::vector<std::uint8_t> frag2_payload(body.begin() + 16, body.begin() + 24);
        const std::vector<std::uint8_t> frag3_payload(body.begin() + 24, body.begin() + 32);

        const auto ip_id = ::tc8::sce::ipv4::reassembly::kReassembly04IpId;

        // Spec wire order: frag 0 → frag 2 → frag 1 → frag 3.
        ::tc8::sce::ipv4::reassembly::emitIpv4Fragment(
            iface, cfg, cfg.arp.dut_iface_mac, ip_id,
            /*offset=*/0, /*MF=*/true, /*ttl=*/64, frag0_payload);
        ::tc8::sce::ipv4::reassembly::emitIpv4Fragment(
            iface, cfg, cfg.arp.dut_iface_mac, ip_id,
            /*offset=*/2, /*MF=*/true, /*ttl=*/64, frag2_payload);
        ::tc8::sce::ipv4::reassembly::emitIpv4Fragment(
            iface, cfg, cfg.arp.dut_iface_mac, ip_id,
            /*offset=*/1, /*MF=*/true, /*ttl=*/64, frag1_payload);
        ::tc8::sce::ipv4::reassembly::emitIpv4Fragment(
            iface, cfg, cfg.arp.dut_iface_mac, ip_id,
            /*offset=*/3, /*MF=*/false, /*ttl=*/64, frag3_payload);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                return "pass";
            case State::Fail_echo_id:        return "fail:echo_id_mismatch_after_unordered_reassembly";
            case State::Fail_echo_seq:       return "fail:echo_seq_mismatch_after_unordered_reassembly";
            case State::Fail_data_mismatch:  return "fail:reassembled_echo_data_mismatch_unordered";
            case State::Fail_timeout:        return "fail:no_echo_reply_after_unordered_reassembly";
            default:                         return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Reassembly04SM, ipv4_reassembly_04)
