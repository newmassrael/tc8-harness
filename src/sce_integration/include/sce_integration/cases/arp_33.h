#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_33_sm.h"

namespace tc8::sce::cases {

using Arp33SM = ::SCE::Generated::arp_33::arp_33;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp33SM>
    : ArpAndUdpBase<cases::Arp33SM> {
    static constexpr std::string_view kCaseId = "ARP_33";
    static constexpr std::string_view kDescription =
        "ARP cache entry merge on two gratuitous Responses from different "
        "MACs — DUT UDP egress eth_dst must equal the second-injected MAC";
    // Gratuitous Response variant of ARP_32: both injections have
    // opcode=2, target_ip = sender_ip = tester_ip, target_hw =
    // broadcast per the TC8 v3.0 spec literal. Requires `arp_accept=1`
    // on the DUT iface (setup-netns.sh enables it) for Linux to learn
    // from gratuitous Responses.
    //
    // target_hw = broadcast is the TC8 spec literal; Linux's
    // `arp_is_garp()` only recognises a Response as gratuitous when
    // target_hw == sender_hw; any other override inside the neighbour
    // entry's 1 s `locktime` is dropped, so an unconditioned Linux DUT
    // keeps MAC1 (fail:udp_eth_dst_is_mac1_not_mac2). The orchestrator
    // sets `locktime=0` for this case (conditioning.rs), which leaves
    // the RFC 826 merge in force. A DUT without the hold passes as-is.
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg,
                         ::tc8::sce::StimulusContext &ctx) {
        ::tc8::stimulus::ArpFrameSpec spec1;
        spec1.opcode = 0x0002;  // gratuitous Response
        spec1.sender_hw = ::tc8::stimulus::kTesterInjectedMac;
        spec1.eth_src = ::tc8::stimulus::kTesterInjectedMac;
        spec1.target_hw = ::tc8::stimulus::kEthBroadcast;  // TC8 spec literal
        spec1.sender_ip_be = cfg.arp.tester_ip;
        spec1.target_ip_be = cfg.arp.tester_ip;
        ::tc8::stimulus::emitArpFromTester(ctx.iface, spec1);

        ::tc8::stimulus::ArpFrameSpec spec2;
        spec2.opcode = 0x0002;
        spec2.sender_hw = ::tc8::stimulus::kTesterInjectedMac2;
        spec2.eth_src = ::tc8::stimulus::kTesterInjectedMac2;
        spec2.target_hw = ::tc8::stimulus::kEthBroadcast;  // TC8 spec literal
        spec2.sender_ip_be = cfg.arp.tester_ip;
        spec2.target_ip_be = cfg.arp.tester_ip;
        ::tc8::stimulus::emitArpFromTester(ctx.iface, spec2);

        emitArpEgressProvocation(ctx.dut, cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp33SM, arp_33)
