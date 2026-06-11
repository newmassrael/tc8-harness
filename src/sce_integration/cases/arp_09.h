#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/upper_tester_client.h"

#include "arp_09_sm.h"

namespace tc8::sce::cases {

using Arp09SM = ::SCE::Generated::arp_09::arp_09;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp09SM>
    : ArpAnyBase<cases::Arp09SM> {
    static constexpr std::string_view kCaseId       = "ARP_09";
    static constexpr std::string_view kSpecSection  = "4.2.4.1";
    static constexpr std::string_view kDescription  =
        "ARP request Protocol Type field shall carry ARP_PROTOCOL_IP (0x0800)";
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
            case State::Fail_proto_type: return "fail:proto_type_not_ipv4";
            case State::Fail_timeout:    return "fail:no_arp_request_within_listen_window";
            default:                     return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp09SM, arp_09)
