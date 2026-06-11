#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_06_sm.h"

namespace tc8::sce::cases {

using Arp06SM = ::SCE::Generated::arp_06::arp_06;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp06SM>
    : ArpAndUdpBase<cases::Arp06SM> {
    static constexpr std::string_view kCaseId = "ARP_06";
    static constexpr std::string_view kSpecSection = "4.2.4.1";
    static constexpr std::string_view kDescription =
        "ARP entry used for UDP egress after gratuitous ARP Response "
        "learning — DUT UDP to tester_ip must carry Ethernet destination = "
        "tester_mac";
    // Gratuitous Response variant of ARP_04's stimulus. Requires
    // `arp_accept=1` on DUT iface (see ARP_05).
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg, std::string_view iface) {
        ::tc8::stimulus::emitArpLearningBoot(iface, cfg.arp.tester_ip, cfg.dut.ip,
                                             ::tc8::stimulus::ArpLearningVariant::GratuitousResponse);
        emitArpEgressProvocation(cfg, iface, cfg.stimulus_timing);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
        case State::Pass:
            return "pass";
        case State::Fail_dut_did_arp_request:
            return "fail:dut_arp_request_after_gratuitous_learning";
        case State::Fail_wrong_eth_dst:
            return "fail:udp_eth_dst_not_tester_mac";
        case State::Fail_timeout:
            return "fail:no_udp_from_dut_within_listen_window";
        default:
            return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp06SM, arp_06)
