#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_18_sm.h"

namespace tc8::sce::cases {

using Arp18SM = ::SCE::Generated::arp_18::arp_18;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp18SM>
    : ArpAnyBase<cases::Arp18SM> {
    static constexpr std::string_view kCaseId = "ARP_18";
    static constexpr std::string_view kSpecSection = "4.2.4.2";
    static constexpr std::string_view kDescription =
        "ARP Request reception with arbitrary target_hw — DUT must reply";
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg, std::string_view iface) {
        ::tc8::stimulus::ArpFrameSpec spec;
        spec.sender_ip_be = cfg.arp.tester_ip;
        spec.target_ip_be = cfg.dut.ip;
        // ARBIT_MAC_ADDR — locally-administered unicast distinct from
        // kTesterInjectedMac and the DUT MAC; any non-zero, non-broadcast
        // value works here, the spec only requires "arbitrary".
        spec.target_hw = {0x02, 0xDE, 0xAD, 0xBE, 0xEF, 0x42};
        ::tc8::stimulus::emitArpFromTester(iface, spec);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp18SM, arp_18)
