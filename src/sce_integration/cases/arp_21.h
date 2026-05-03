#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_21_sm.h"

namespace tc8::sce::cases {

using Arp21SM = ::SCE::Generated::arp_21::arp_21;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp21SM>
    : ArpAnyBase<cases::Arp21SM> {
    static constexpr std::string_view kCaseId = "ARP_21";
    static constexpr std::string_view kSpecSection = "4.2.4.2";
    static constexpr std::string_view kDescription =
        "ARP Request with unknown hw_type — DUT must drop and not reply";
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg, std::string_view iface) {
        ::tc8::stimulus::ArpFrameSpec spec;
        spec.sender_ip_be = cfg.arp.tester_ip;
        spec.target_ip_be = cfg.arp.dut_real_ip;
        spec.hw_type = 0xFFFF;  // ARP_HARDWARE_TYPE_UNKNOWN
        ::tc8::stimulus::emitArpFromTester(iface, spec);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
        case State::Pass:
            return "pass";
        case State::Fail_unexpected_reply:
            return "fail:dut_replied_to_malformed_request";
        default:
            return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp21SM, arp_21)
