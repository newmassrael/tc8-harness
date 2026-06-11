#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_34_sm.h"

namespace tc8::sce::cases {

using Arp34SM = ::SCE::Generated::arp_34::arp_34;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp34SM>
    : ArpAndUdpBase<cases::Arp34SM> {
    static constexpr std::string_view kCaseId = "ARP_34";
    static constexpr std::string_view kSpecSection = "4.2.4.2";
    static constexpr std::string_view kDescription =
        "ARP cache entry merge on Request-then-Response — DUT UDP egress "
        "eth_dst must equal the second-injected MAC";
    // Heterogeneous variant of ARP_32: spec1 is an ARP Request (MAC1),
    // spec2 is a gratuitous ARP Response (MAC2). Both inject an entry for
    // `<tester_ip, MAC?>`; the merge clause still applies.
    //
    // spec2.target_hw = broadcast per the TC8 v3.0 spec literal. Linux's
    // `arp_is_garp()` rejects this shape (recognises only target_hw ==
    // sender_hw), so a Linux DUT does NOT apply the RFC 826 merge and
    // the second-MAC dominance does not materialise on its UDP egress
    // (cache stays at MAC1 from the spec1 Request). Linux DUT therefore
    // lands fail_used_mac1 and is excluded from CI green via grep
    // filter in .github/workflows/smoke-test.yml. A spec-compliant
    // DUT that honours RFC 826 merge regardless of target_hw lands
    // pass without filter.
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg, std::string_view iface) {
        ::tc8::stimulus::ArpFrameSpec spec1;
        spec1.opcode = 0x0001;  // Request
        spec1.sender_hw = ::tc8::stimulus::kTesterInjectedMac;
        spec1.eth_src = ::tc8::stimulus::kTesterInjectedMac;
        spec1.sender_ip_be = cfg.arp.tester_ip;
        spec1.target_ip_be = cfg.dut.ip;
        ::tc8::stimulus::emitArpFromTester(iface, spec1);

        ::tc8::stimulus::ArpFrameSpec spec2;
        spec2.opcode = 0x0002;  // gratuitous Response
        spec2.sender_hw = ::tc8::stimulus::kTesterInjectedMac2;
        spec2.eth_src = ::tc8::stimulus::kTesterInjectedMac2;
        spec2.target_hw = ::tc8::stimulus::kEthBroadcast;  // TC8 spec literal
        spec2.sender_ip_be = cfg.arp.tester_ip;
        spec2.target_ip_be = cfg.arp.tester_ip;
        ::tc8::stimulus::emitArpFromTester(iface, spec2);

        emitArpEgressProvocation(cfg, iface, cfg.stimulus_timing);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
        case State::Pass:
            return "pass";
        case State::Fail_used_mac1:
            return "fail:udp_eth_dst_is_mac1_not_mac2";
        case State::Fail_unknown_mac:
            return "fail:udp_eth_dst_neither_mac1_nor_mac2";
        case State::Fail_dut_arp_request:
            return "fail:dut_arp_request_after_double_injection";
        case State::Fail_timeout:
            return "fail:no_udp_from_dut_within_listen_window";
        default:
            return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp34SM, arp_34)
