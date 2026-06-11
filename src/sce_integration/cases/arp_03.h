#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"
#include "stimulus/upper_tester_client.h"

#include "arp_03_sm.h"

namespace tc8::sce::cases {

using Arp03SM = ::SCE::Generated::arp_03::arp_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp03SM>
    : ArpAnyBase<cases::Arp03SM> {
    static constexpr ::tc8::BpfGroup kBpfGroup = ::tc8::BpfGroup::ArpAndUdp;

    // UDP is in the capture filter (ArpAndUdp BPF group) but ARP_03's
    // pass criterion is absence of ARP Request; UDP observation is
    // irrelevant here — the inherited ArpAnyBase dispatch lets the
    // UDP variant fall through silently.
    static constexpr std::string_view kCaseId = "ARP_03";
    static constexpr std::string_view kSpecSection = "4.2.4.1";
    static constexpr std::string_view kDescription =
        "ARP entry learned on ARP Request — DUT must NOT emit an ARP Request "
        "after tester pre-populates the cache via an ARP Request";
    // Two-phase stimulus:
    //   1. Inject an ARP Request sourced from kTesterInjectedMac with
    //      sender-IP = tester_ip, target-IP = dut_iface_ip. DUT learns
    //      <tester_ip, kTesterInjectedMac> via RFC 826 §2.3 reception.
    //   2. UT 0x02 egress-provocation stimulus (same as ARP_07..15) —
    //      triggers DUT unicast UDP back to tester_ip, exercising the
    //      learned cache entry. A conformant DUT sends the UDP without
    //      an intervening ARP Request.
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg, std::string_view iface) {
        ::tc8::stimulus::emitArpLearningBoot(iface, cfg.arp.tester_ip, cfg.arp.dut_real_ip,
                                             ::tc8::stimulus::ArpLearningVariant::Request);
        ::tc8::stimulus::emitTriggerSendUdpBoot(iface, cfg.ipv4.tester_ip, cfg.arp.dut_real_ip,
                                                cfg.arp.dut_real_mac, cfg.stimulus_timing);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
        case State::Pass:
            return "pass";
        case State::Fail_unexpected_arp_request:
            return "fail:dut_arp_request_after_cache_populated";
        default:
            return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp03SM, arp_03)
