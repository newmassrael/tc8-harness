#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_35_neg_sm.h"

namespace tc8::sce::cases {

using Arp35NegSM = ::SCE::Generated::arp_35_neg::arp_35_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp35NegSM>
    : ArpIngressFaultNegProvokedBase<cases::Arp35NegSM> {
    static constexpr std::string_view kCaseId      = "ARP_35_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_35: the lwIP kArpFaultIgnoreLearn ingress flavor "
        "swallows the teaching Request, so the DUT holds no entry and emits its own "
        "Request; a conformant DUT resolves from what it was taught";
    // The positive's stimulus, unchanged: a gratuitous Response then a Request. Only
    // the Request is swallowed (the flavour is opcode-1 gated), and on this fixture
    // that is the only teaching that would have landed anyway — lwIP's etharp creates
    // no entry from a gratuitous Response, which is what ARP_06's known-fail records.
    // So this case's SECOND injection is its effective one, and suppressing it leaves
    // the table empty. That asymmetry is also why ARP_35 has no stale-MAC negative:
    // with no first entry to keep, kArpFaultIgnoreUpdate would find nothing already
    // held and swallow nothing.
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg,
                         std::string_view iface, ::tc8::sce::IDutControl &dut) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kArpFaultIgnoreLearn);
        ::tc8::stimulus::ArpFrameSpec spec1;
        spec1.opcode = 0x0002;  // gratuitous Response
        spec1.sender_hw = ::tc8::stimulus::kTesterInjectedMac;
        spec1.eth_src = ::tc8::stimulus::kTesterInjectedMac;
        spec1.target_hw = ::tc8::stimulus::kTesterInjectedMac;  // == sender_hw
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

        emitArpEgressProvocation(dut, cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp35NegSM, arp_35_neg)
