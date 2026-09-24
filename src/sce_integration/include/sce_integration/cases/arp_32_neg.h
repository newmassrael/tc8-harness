#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_32_neg_sm.h"

namespace tc8::sce::cases {

using Arp32NegSM = ::SCE::Generated::arp_32_neg::arp_32_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp32NegSM>
    : ArpIngressFaultNegProvokedBase<cases::Arp32NegSM> {
    static constexpr std::string_view kCaseId      = "ARP_32_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_32: the lwIP kArpFaultIgnoreLearn ingress flavor "
        "swallows BOTH teaching Requests, so the DUT holds no entry and emits its "
        "own Request; a conformant DUT resolves from what it was taught twice";
    // The positive's stimulus, unchanged, with the flavor armed FIRST so the hook is
    // live before either teaching arrives.
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

TC8_REGISTER_CASE(::tc8::sce::cases::Arp32NegSM, arp_32_neg)
