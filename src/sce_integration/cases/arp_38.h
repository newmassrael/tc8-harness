#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_38_sm.h"

namespace tc8::sce::cases {

using Arp38SM = ::SCE::Generated::arp_38::arp_38;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp38SM>
    : ArpAndUdpBase<cases::Arp38SM> {
    static constexpr std::string_view kCaseId = "ARP_38";
    static constexpr std::string_view kSpecSection = "4.2.4.2";
    static constexpr std::string_view kDescription =
        "Non-gratuitous ARP Response with target_ip != DUT IP — DUT must "
        "drop and emit its own ARP Request on subsequent UDP egress";
    // Stimulus: non-gratuitous Response where `target_proto_ip` is an
    // unused IPv4 host (172.16.0.99 — inside the /24 but unassigned). RFC
    // 826 RFC 826 §2.3 step 4 ("Am I the target protocol address?") drops the
    // frame. DUT's cache stays cold for `tester_ip`. Same post-drop flow
    // as ARP_22/28.
    //
    // Unused-IP value is hardcoded here rather than threaded through the
    // CLI because the specific numeric is test-scope only — the SCXML
    // has no comparison against it. 172.16.0.99 is well clear of the
    // .1 / .2 topology endpoints and chosen to survive netns /24 changes
    // by staying in the same subnet.
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg, std::string_view iface) {
        constexpr std::uint32_t kUnusedTargetIpBe =
            (static_cast<std::uint32_t>(99) << 24) |
            (static_cast<std::uint32_t>(0) << 16) |
            (static_cast<std::uint32_t>(16) << 8) |
            static_cast<std::uint32_t>(172);  // 172.16.0.99 in network byte order
        ::tc8::stimulus::ArpFrameSpec spec;
        spec.opcode = 0x0002;  // Response (non-gratuitous)
        spec.sender_ip_be = cfg.arp.tester_ip;
        spec.target_ip_be = kUnusedTargetIpBe;
        // eth_dst defaults to broadcast per spec; target_hw stays kEthZero
        // (standard for Responses where the target MAC is unknown to the
        // sender — matches the spec's silence on target_hw content for
        // this specific case).
        ::tc8::stimulus::emitArpFromTester(iface, spec);
        emitArpEgressProvocation(cfg, iface, cfg.stimulus_timing);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
        case State::Pass:
            return "pass";
        case State::Fail_udp_used_injected_mac:
            return "fail:udp_eth_dst_matched_dropped_frame_mac";
        case State::Fail_no_dut_arp_request:
            return "fail:no_arp_request_within_listen_window";
        default:
            return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp38SM, arp_38)
