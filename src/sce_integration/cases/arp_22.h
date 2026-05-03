#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "arp_22_sm.h"

namespace tc8::sce::cases {

using Arp22SM = ::SCE::Generated::arp_22::arp_22;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp22SM>
    : ArpAndUdpBase<cases::Arp22SM> {
    static constexpr std::string_view kCaseId = "ARP_22";
    static constexpr std::string_view kSpecSection = "4.2.4.2";
    static constexpr std::string_view kDescription =
        "Gratuitous ARP Response with unknown hw_type — DUT must drop and "
        "emit its own ARP Request on subsequent UDP egress";
    // Two-phase stimulus:
    //   1. Inject a gratuitous ARP Response with hw_type = 0xFFFF
    //      (ARP_HARDWARE_TYPE_UNKNOWN). Linux drops the frame at its ARP
    //      reception algorithm (RFC 826 §2.3 step 1: "Do I have the
    //      hardware type in ar$hrd?") so the DUT's cache is NOT updated.
    //   2. Subscribe-Nack stimulus to force DUT unicast UDP egress. With
    //      no cache entry for `tester_ip`, a conformant DUT must emit its
    //      own ARP Request to resolve the tester MAC before the UDP.
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg, std::string_view iface) {
        ::tc8::stimulus::ArpFrameSpec spec;
        spec.hw_type = 0xFFFF;  // ARP_HARDWARE_TYPE_UNKNOWN
        spec.opcode = 0x0002;   // Response
        spec.target_hw = ::tc8::stimulus::kEthBroadcast;
        spec.sender_ip_be = cfg.arp.tester_ip;
        spec.target_ip_be = cfg.arp.tester_ip;  // gratuitous: target_ip == sender_ip
        ::tc8::stimulus::emitArpFromTester(iface, spec);
        ::tc8::stimulus::emitSubscribeEventgroupBoot(iface, ::tc8::stimulus::SubscribeEventgroupTarget{},
                                                     cfg.stimulus_timing);
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

TC8_REGISTER_CASE(::tc8::sce::cases::Arp22SM, arp_22)
