#pragma once

#include <string_view>
#include <chrono>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"
#include "stimulus/upper_tester_client.h"

#include "arp_40_sm.h"

namespace tc8::sce::cases {

using Arp40SM = ::SCE::Generated::arp_40::arp_40;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp40SM>
    : ArpAndUdpBase<cases::Arp40SM> {
    static constexpr std::string_view kCaseId = "ARP_40";
    static constexpr std::string_view kSpecSection = "4.2.4.2";
    static constexpr std::string_view kDescription =
        "ARP learning via received Response — DUT must populate cache "
        "from tester-injected Response and use it for subsequent UDP egress";
    // Byte-sibling stimulus to ARP_39 — see arp_39.h for the wire-level
    // rationale (tester `arp_ignore=8` suppresses kernel auto-reply,
    // pending UDP drains via neigh_resolve_output queue once cache
    // resolves). The only field-level differences are:
    //   * `opcode = 0x0002` (ARP Response, not Request).
    //   * `sender_hw = MAC-ADDR3` (distinct attribution from MAC1/MAC2).
    //   * `target_hw = BROADCAST` per spec (Linux still updates the
    //     cache from a non-gratuitous Response when arp_accept=1, the
    //     setup-netns.sh default for §4.2 cases).
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg, std::string_view iface) {
        ::tc8::stimulus::BootTiming ut_timing;
        ut_timing.initial_wait = std::chrono::milliseconds(1500);
        ut_timing.retry_interval = std::chrono::milliseconds(0);
        ut_timing.total_emits = 1;
        ::tc8::stimulus::emitTriggerSendUdpBoot(iface, cfg.ipv4.tester_ip, cfg.arp.dut_real_ip,
                                                cfg.arp.dut_real_mac, ut_timing);

        ::tc8::stimulus::ArpFrameSpec spec;
        spec.opcode = 0x0002;  // Response — spec ARP_40 inject form
        spec.sender_hw = ::tc8::stimulus::kTesterInjectedMac3;
        spec.eth_src = ::tc8::stimulus::kTesterInjectedMac3;
        spec.target_hw = ::tc8::stimulus::kEthBroadcast;  // per spec ARP_40 step 5
        spec.sender_ip_be = cfg.arp.tester_ip;
        spec.target_ip_be = cfg.arp.dut_real_ip;
        ::tc8::stimulus::emitArpFromTester(iface, spec);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
        case State::Pass:
            return "pass";
        case State::Fail_no_dut_request:
            return "fail:no_dut_arp_request_within_listen_window";
        case State::Fail_udp_before_dut_request:
            return "fail:udp_egress_before_dut_arp_request";
        case State::Fail_wrong_eth_dst:
            return "fail:udp_eth_dst_not_injected_mac3";
        case State::Fail_no_udp:
            return "fail:no_udp_after_arp_learning";
        default:
            return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp40SM, arp_40)
