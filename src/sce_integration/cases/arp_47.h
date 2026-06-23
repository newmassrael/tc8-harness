#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_47_sm.h"

namespace tc8::sce::cases {

using Arp47SM = ::SCE::Generated::arp_47::arp_47;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp47SM>
    : ArpAnyBase<cases::Arp47SM> {
    static constexpr std::string_view kCaseId = "ARP_47";
    static constexpr std::string_view kDescription =
        "ARP Response hw_addr_len equals ETHERNET_ADDR_LEN (6)";
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg, std::string_view iface) {
        ::tc8::stimulus::ArpFrameSpec spec;
        spec.sender_ip_be = cfg.arp.tester_ip;
        spec.target_ip_be = cfg.dut.ip;
        ::tc8::stimulus::emitArpFromTester(iface, spec);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp47SM, arp_47)
