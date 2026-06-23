#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_35_sm.h"

namespace tc8::sce::cases {

using Arp35SM = ::SCE::Generated::arp_35::arp_35;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp35SM>
    : ArpAndUdpBase<cases::Arp35SM> {
    static constexpr std::string_view kCaseId = "ARP_35";
    static constexpr std::string_view kDescription =
        "ARP cache entry merge on Response-then-Request — DUT UDP egress "
        "eth_dst must equal the second-injected MAC";
    // Inverse of ARP_34: spec1 is a gratuitous ARP Response (MAC1), spec2
    // is an ARP Request (MAC2). The second injection (Request) must still
    // merge-update the entry; Linux's neigh learning is opcode-agnostic
    // once the frame passes RFC 826 §2.3 reception.
    //
    // spec1.target_hw = sender_hw (not broadcast per TC8 spec): see the
    // Linux `arp_is_garp()` note in arp_33.h. In this case the first
    // frame creates the entry via the arp_accept+REPLY path even with
    // target_hw=broadcast, but keeping target_hw=sender_hw is the
    // semantically correct gratuitous form and matches the sibling
    // cache-merge cases in Group C.
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg, std::string_view iface) {
        ::tc8::stimulus::ArpFrameSpec spec1;
        spec1.opcode = 0x0002;  // gratuitous Response
        spec1.sender_hw = ::tc8::stimulus::kTesterInjectedMac;
        spec1.eth_src = ::tc8::stimulus::kTesterInjectedMac;
        spec1.target_hw = ::tc8::stimulus::kTesterInjectedMac;  // == sender_hw (Linux garp recognition)
        spec1.sender_ip_be = cfg.arp.tester_ip;
        spec1.target_ip_be = cfg.arp.tester_ip;
        ::tc8::stimulus::emitArpFromTester(iface, spec1);

        ::tc8::stimulus::ArpFrameSpec spec2;
        spec2.opcode = 0x0001;  // Request
        spec2.sender_hw = ::tc8::stimulus::kTesterInjectedMac2;
        spec2.eth_src = ::tc8::stimulus::kTesterInjectedMac2;
        spec2.sender_ip_be = cfg.arp.tester_ip;
        spec2.target_ip_be = cfg.dut.ip;
        ::tc8::stimulus::emitArpFromTester(iface, spec2);

        emitArpEgressProvocation(cfg, iface, cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp35SM, arp_35)
