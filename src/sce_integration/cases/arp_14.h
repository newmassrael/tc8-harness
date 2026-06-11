#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/upper_tester_client.h"

#include "arp_14_sm.h"

namespace tc8::sce::cases {

using Arp14SM = ::SCE::Generated::arp_14::arp_14;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp14SM>
    : ArpAnyBase<cases::Arp14SM> {
    static constexpr std::string_view kCaseId       = "ARP_14";
    static constexpr std::string_view kSpecSection  = "4.2.4.1";
    static constexpr std::string_view kDescription  =
        "ARP request Source IP Address shall carry the configured DIface-0 IPv4";
    // UT 0x02 egress-provocation stimulus — see arp_07.h.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitTriggerSendUdpBoot(iface, cfg.ipv4.tester_ip,
            cfg.arp.dut_real_ip, cfg.arp.dut_real_mac, cfg.stimulus_timing);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:            return "pass";
            case State::Fail_sender_ip:  return "fail:sender_proto_ip_not_dut_iface";
            case State::Fail_timeout:    return "fail:no_arp_request_within_listen_window";
            default:                     return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp14SM, arp_14)
