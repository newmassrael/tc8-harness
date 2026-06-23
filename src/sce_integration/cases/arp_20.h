#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_20_sm.h"

namespace tc8::sce::cases {

using Arp20SM = ::SCE::Generated::arp_20::arp_20;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp20SM>
    : ArpAnyBase<cases::Arp20SM> {
    static constexpr std::string_view kCaseId = "ARP_20";
    static constexpr std::string_view kDescription =
        "ARP Request reception with hw_type=Ethernet (correct) — DUT must reply";
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg, std::string_view iface) {
        ::tc8::stimulus::ArpFrameSpec spec;
        spec.sender_ip_be = cfg.arp.tester_ip;
        spec.target_ip_be = cfg.dut.ip;
        spec.hw_type = 0x0001;  // ARP_HARDWARE_ETHERNET
        ::tc8::stimulus::emitArpFromTester(iface, spec);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp20SM, arp_20)
