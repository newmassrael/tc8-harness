#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_fragments_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_fragments_01_sm.h"

namespace tc8::sce::cases {

using Ipv4Fragments01SM = ::SCE::Generated::ipv4_fragments_01::ipv4_fragments_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Fragments01SM>
    : Ipv4FragmentEchoBase<cases::Ipv4Fragments01SM> {
    static constexpr std::string_view kCaseId      = "IPV4_FRAGMENTS_01";
    static constexpr std::string_view kSpecSection = "4.4.4.6";
    static constexpr std::string_view kDescription =
        "DUT reassembles a 2-fragment Echo Request and emits an Echo "
        "Reply whose Identifier, Sequence Number, and Data match the "
        "reassembled Echo Request (RFC 791 §3.2, RFC 1122 §3.3.2)";

    // Send two IP fragments carrying the 16 B reassembled Echo
    // Request (8 B ICMP header + 8 B payload). `emitFragmentPair`
    // builds the body ONCE so the ICMP checksum — computed over the
    // full reassembled region — validates on the DUT side after
    // reassembly. Both fragments carry the same (src, dst, id,
    // protocol) tuple, so the DUT's reassembly bucket completes and
    // its IP layer hands the datagram to the ICMP echo handler.
    //
    // L2 destination is DUT-unicast. Linux's IP reassembly path
    // accepts fragments with any pkt_type, but staying unicast rules
    // out any L2-dispatch skew and keeps the envelope symmetric with
    // the §4.3 error cases (TYPE_04, ERROR_02/03) that exercise
    // related fragment paths.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::ipv4::fragments::FragmentPairParams params{};
        // Defaults already encode the FRAGMENTS_01 positive tuple:
        // src_ip_frag0/1 = tester_ip (0 → cfg default), ip_id = id1
        // on both halves, ip_protocol = ICMP on both halves.
        ::tc8::sce::ipv4::fragments::emitFragmentPair(
            iface, cfg, cfg.arp.dut_iface_mac, params);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                 return "pass";
            case State::Fail_echo_id:         return "fail:echo_id_mismatch";
            case State::Fail_echo_seq:        return "fail:echo_seq_mismatch";
            case State::Fail_data_mismatch:   return "fail:reassembled_echo_data_mismatch";
            case State::Fail_timeout:         return "fail:no_echo_reply_after_reassembly";
            default:                          return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Fragments01SM, ipv4_fragments_01)
