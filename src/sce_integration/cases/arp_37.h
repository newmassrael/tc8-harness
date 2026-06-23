#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_37_sm.h"

namespace tc8::sce::cases {

using Arp37SM = ::SCE::Generated::arp_37::arp_37;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp37SM>
    : ArpAnyBase<cases::Arp37SM> {
    static constexpr std::string_view kCaseId = "ARP_37";
    static constexpr std::string_view kDescription =
        "ARP Request with target_ip != DUT IP — DUT must not reply";
    // <IP-FIRST-UNUSED-ADDR-INTERFACE-1> per spec — an address on the
    // /24 subnet not currently bound to DUT or tester. 10.99.99.99 is
    // outside 172.16.0.0/24 which guarantees Linux sees it as
    // "not one of mine" and drops the Request without reply.
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg, std::string_view iface) {
        ::tc8::stimulus::ArpFrameSpec spec;
        spec.sender_ip_be = cfg.arp.tester_ip;
        // 10.99.99.99 in network byte order: 0x0A 0x63 0x63 0x63.
        spec.target_ip_be = 0x6363630Au;
        ::tc8::stimulus::emitArpFromTester(iface, spec);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp37SM, arp_37)
