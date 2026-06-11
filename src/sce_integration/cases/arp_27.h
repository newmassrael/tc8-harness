#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_27_sm.h"

namespace tc8::sce::cases {

using Arp27SM = ::SCE::Generated::arp_27::arp_27;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp27SM>
    : ArpAnyBase<cases::Arp27SM> {
    static constexpr std::string_view kCaseId = "ARP_27";
    static constexpr std::string_view kSpecSection = "4.2.4.2";
    static constexpr std::string_view kDescription =
        "ARP Request with unknown proto_type — DUT must drop and not reply";
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg, std::string_view iface) {
        ::tc8::stimulus::ArpFrameSpec spec;
        spec.sender_ip_be = cfg.arp.tester_ip;
        spec.target_ip_be = cfg.dut.ip;
        spec.proto_type = 0xFFFF;  // ARP_PROTOCOL_UNKNOWN
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

TC8_REGISTER_CASE(::tc8::sce::cases::Arp27SM, arp_27)
