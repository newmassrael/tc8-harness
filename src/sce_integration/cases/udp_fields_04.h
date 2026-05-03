#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/cases/udp_fields_01.h"  // kUdpFieldsTesterSrcPort
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_fields_04_sm.h"

namespace tc8::sce::cases {

using UdpFields04SM = ::SCE::Generated::udp_fields_04::udp_fields_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpFields04SM>
    : UdpAnyBase<cases::UdpFields04SM> {
    static constexpr std::string_view kCaseId      = "UDP_FIELDS_04";
    static constexpr std::string_view kSpecSection = "4.6.5.4";
    static constexpr std::string_view kDescription =
        "DUT can send UDP to the same destination port at two distinct "
        "destination IP addresses (Topology 2; RFC 768 'Fields' MUST)";
    static constexpr int              kTopology    = 2;

    // Phase 1 (synchronous): DUT → Host-1-IP via OpTriggerSendUdp.
    // Phase 2 (scheduled on Listening_phase2 entry): DUT → Host-2-IP
    // (kUdpHost2IpBe = 172.16.0.3). Per-case src_port 20040 keeps the
    // wire frames disambiguated from other §4.6 egress cases.
    //
    // The DUT's egress ARP for 172.16.0.3 resolves via the
    // NUD_PERMANENT entry pinned by smoke-test.sh's bring_up_worker;
    // tester-side never aliases the IP, so Linux's IP layer drops the
    // unmatched-dst inbound silently while pcap on AF_PACKET ETH_P_ALL
    // observes the wire frame regardless.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::udp::emitTriggerSendUdp(
            cfg, iface,
            /*req_id=*/1,
            /*dut_src_port=*/20040,
            /*target_ip_be=*/cfg.ipv4.tester_ip,
            /*target_port=*/::tc8::sce::udp::kDataPort,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            static_cast<std::uint16_t>(::tc8::sce::udp::kUdpDefaultData.size()),
            cases::kUdpFieldsTesterSrcPort,
            cfg.arp.dut_real_mac);

        std::string iface_copy(iface);
        ::tc8::TestConfig cfg_copy = cfg;
        const auto dut_mac = cfg.arp.dut_real_mac;
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_phase2),
            [iface_copy, cfg_copy, dut_mac]() {
                ::tc8::sce::udp::emitTriggerSendUdp(
                    cfg_copy, iface_copy,
                    /*req_id=*/2,
                    /*dut_src_port=*/20040,
                    /*target_ip_be=*/::tc8::sce::udp::kUdpHost2IpBe,
                    /*target_port=*/::tc8::sce::udp::kDataPort,
                    ::tc8::sce::udp::kUdpDefaultData.data(),
                    static_cast<std::uint16_t>(::tc8::sce::udp::kUdpDefaultData.size()),
                    cases::kUdpFieldsTesterSrcPort,
                    dut_mac,
                    /*initial_wait=*/std::chrono::milliseconds(0));
            });
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                              return "pass";
            case State::Fail_phase1_no_host1_egress:       return "fail:no_dut_originated_udp_to_host1_within_listen_window";
            case State::Fail_phase2_no_host2_egress:       return "fail:no_dut_originated_udp_to_host2_within_listen_window";
            default:                                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpFields04SM, udp_fields_04)
