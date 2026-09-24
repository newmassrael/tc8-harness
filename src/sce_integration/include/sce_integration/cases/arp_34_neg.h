#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_34_neg_sm.h"

namespace tc8::sce::cases {

using Arp34NegSM = ::SCE::Generated::arp_34_neg::arp_34_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp34NegSM>
    : ArpIngressFaultNegProvokedBase<cases::Arp34NegSM> {
    static constexpr std::string_view kCaseId      = "ARP_34_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_34: the lwIP kArpFaultIgnoreLearn ingress flavor "
        "swallows the teaching Request, and the gratuitous Response that follows can "
        "only UPDATE, so no entry exists and the DUT emits its own Request";
    // The positive's stimulus, unchanged. Why the opcode-1-only flavour is enough here
    // even though the SECOND injection is a Response: that Response is gratuitous
    // (target_ip == sender_ip), so it is not `for_us` and lwIP's etharp handles it
    // FIND_ONLY — it can refresh an existing entry but never create one. Suppress the
    // Request that created the entry and the Response has nothing left to find, which
    // is also why the positive passes on this fixture while ARP_06, whose only teaching
    // IS a gratuitous Response, is a known-fail here.
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg,
                         std::string_view iface, ::tc8::sce::IDutControl &dut) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kArpFaultIgnoreLearn);
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
        spec2.target_hw = ::tc8::stimulus::kEthBroadcast;
        spec2.sender_ip_be = cfg.arp.tester_ip;
        spec2.target_ip_be = cfg.arp.tester_ip;
        ::tc8::stimulus::emitArpFromTester(iface, spec2);

        emitArpEgressProvocation(dut, cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp34NegSM, arp_34_neg)
