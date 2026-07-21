#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_42_sm.h"

namespace tc8::sce::cases {

using Arp42SM = ::SCE::Generated::arp_42::arp_42;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp42SM>
    : ArpAnyBase<cases::Arp42SM> {
    static constexpr std::string_view kCaseId = "ARP_42";
    static constexpr std::string_view kDescription =
        "ARP Response received — DUT must not reply to a Response";
    // Non-gratuitous Response: target_hw is the tester's injected MAC so
    // the frame is addressed to us, eth_dst is unicast back at the tester
    // (Linux still processes broadcast-dst Responses but the spec says
    // unicast reply). eth_dst defaults to broadcast, which also works;
    // keep broadcast for simplicity, matching ARP_33's gratuitous frame.
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg, std::string_view iface) {
        ::tc8::stimulus::ArpFrameSpec spec;
        spec.opcode = 0x0002;  // Response
        spec.sender_ip_be = cfg.arp.tester_ip;
        spec.target_ip_be = cfg.dut.ip;
        spec.target_hw = cfg.dut.mac;  // addressed to DUT
        ::tc8::stimulus::emitArpFromTester(iface, spec);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp42SM, arp_42)
