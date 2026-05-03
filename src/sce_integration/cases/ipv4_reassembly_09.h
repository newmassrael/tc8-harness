#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_fragments_common.h"
#include "sce_integration/ipv4_reassembly_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_reassembly_09_sm.h"

namespace tc8::sce::cases {

using Ipv4Reassembly09SM = ::SCE::Generated::ipv4_reassembly_09::ipv4_reassembly_09;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Reassembly09SM>
    : Ipv4FragmentEchoBase<cases::Ipv4Reassembly09SM> {
    static constexpr std::string_view kCaseId      = "IPV4_REASSEMBLY_09";
    static constexpr std::string_view kSpecSection = "4.4.4.7";
    static constexpr std::string_view kDescription =
        "DUT discards an IPv4 Packet whose MF=1 with no following "
        "fragment — reassembly bucket times out, no Echo Reply "
        "(RFC 791 §3.2)";

    // Single IPv4 fragment with MF=1 carrying the full 16 B Echo
    // Request body (8 B ICMP header + 8 B kFragmentsEchoPayload) at
    // offset=0. Because MF=1 says "more fragments coming" and no
    // offset>0 ever arrives, the DUT's IP reassembly bucket never
    // completes; Linux's `net.ipv4.ipfrag_time` (default 30 s, not
    // toggled for this case) drops it after timeout. The 3 s SCXML
    // deadline is well below ipfrag_time, so the DUT remains silent
    // throughout the listen window.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        const auto body = ::tc8::sce::ipv4::reassembly::buildReassembly16BEchoBody();
        ::tc8::sce::ipv4::reassembly::emitIpv4Fragment(
            iface, cfg, cfg.arp.dut_iface_mac,
            ::tc8::sce::ipv4::reassembly::kReassembly09IpId,
            /*fragment_offset=*/0,
            /*more_fragments=*/true,
            /*ttl=*/64,
            body);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:              return "pass";
            case State::Fail_dut_replied:  return "fail:dut_replied_to_single_mf1_fragment";
            default:                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Reassembly09SM, ipv4_reassembly_09)
