#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_26_sm.h"

namespace tc8::sce::cases {

using Arp26SM = ::SCE::Generated::arp_26::arp_26;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp26SM>
    : ArpAnyBase<cases::Arp26SM> {
    static constexpr std::string_view kCaseId = "ARP_26";
    static constexpr std::string_view kSpecSection = "4.2.4.2";
    static constexpr std::string_view kDescription =
        "ARP Request reception with proto_type=IPv4 (correct) — DUT must reply";
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg, std::string_view iface) {
        ::tc8::stimulus::ArpFrameSpec spec;
        spec.sender_ip_be = cfg.arp.tester_ip;
        spec.target_ip_be = cfg.dut.ip;
        spec.proto_type = 0x0800;  // ARP_PROTOCOL_IP
        ::tc8::stimulus::emitArpFromTester(iface, spec);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
        case State::Pass:
            return "pass";
        case State::Fail_no_reply:
            return "fail:no_arp_reply_within_listen_window";
        default:
            return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp26SM, arp_26)
