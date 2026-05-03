#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "arp_33_sm.h"

namespace tc8::sce::cases {

using Arp33SM = ::SCE::Generated::arp_33::arp_33;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp33SM>
    : ArpAndUdpBase<cases::Arp33SM> {
    static constexpr std::string_view kCaseId = "ARP_33";
    static constexpr std::string_view kSpecSection = "4.2.4.2";
    static constexpr std::string_view kDescription =
        "ARP cache entry merge on two gratuitous Responses from different "
        "MACs — DUT UDP egress eth_dst must equal the second-injected MAC";
    // Gratuitous Response variant of ARP_32: both injections have
    // opcode=2, target_ip = sender_ip = tester_ip, target_hw = sender_hw.
    // Requires `arp_accept=1` on the DUT iface (setup-netns.sh enables
    // it) for Linux to learn from gratuitous Responses.
    //
    // target_hw = sender_hw rather than broadcast (the TC8 spec text): the
    // Linux kernel's `arp_is_garp()` only recognises a Response as
    // gratuitous when target_hw == sender_hw, and only then does it
    // apply the RFC 826 "merge" override that this case verifies.
    // target_hw = broadcast would leave the second frame stuck behind
    // the 1 s LOCKTIME and the merge would silently skip. Deviating from
    // the spec's literal target_hw keeps the test's *pass criterion*
    // (second-MAC dominance on DUT UDP egress) verifiable on a Linux
    // tc8-dut; a real DUT under test should implement RFC 826 merge
    // regardless of target_hw.
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
        spec2.opcode = 0x0002;
        spec2.sender_hw = ::tc8::stimulus::kTesterInjectedMac2;
        spec2.eth_src = ::tc8::stimulus::kTesterInjectedMac2;
        spec2.target_hw = ::tc8::stimulus::kTesterInjectedMac2;
        spec2.sender_ip_be = cfg.arp.tester_ip;
        spec2.target_ip_be = cfg.arp.tester_ip;
        ::tc8::stimulus::emitArpFromTester(iface, spec2);

        ::tc8::stimulus::emitSubscribeEventgroupBoot(iface, ::tc8::stimulus::SubscribeEventgroupTarget{},
                                                     cfg.stimulus_timing);
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

TC8_REGISTER_CASE(::tc8::sce::cases::Arp33SM, arp_33)
