#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_45_neg_sm.h"

namespace tc8::sce::cases {

using Arp45NegSM = ::SCE::Generated::arp_45_neg::arp_45_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp45NegSM>
    : ArpEgressFaultNegBase<cases::Arp45NegSM> {
    static constexpr std::string_view kCaseId      = "ARP_45_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_45's second-Response guard: kArpFaultResponseTargetHwWrong "
        "is armed BETWEEN the two Requests, so the first Reply answers correctly and only "
        "the second carries a target_hw that is not the Request's sender";
    // The positive's two Requests, with the arm placed between them. Arming before the
    // first would corrupt Reply 1 and land the positive's FIRST guard, which this negative
    // is not the one for: one run reaches one final, and the per-final coverage map exists
    // because a multi-guard case needs a negative per guard.
    //
    // The settle after the arm is the same kFlavorArmSettle the ingress arms use: the arm
    // is a raw-injected UT frame handled on the DUT's UT thread, while the Reply is emitted
    // from the tcpip thread, so the two need a gap rather than an ordering guarantee.
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg, std::string_view iface) {
        ::tc8::stimulus::ArpFrameSpec spec1;
        spec1.opcode = 0x0001;  // Request
        spec1.sender_hw = ::tc8::stimulus::kTesterInjectedMac;
        spec1.eth_src = ::tc8::stimulus::kTesterInjectedMac;
        spec1.sender_ip_be = cfg.arp.tester_ip;
        spec1.target_ip_be = cfg.dut.ip;
        ::tc8::stimulus::emitArpFromTester(iface, spec1);

        emitEgressFlavorArmMidStream(cfg, iface, ::tc8::ut::kArpFaultResponseTargetHwWrong);
        std::this_thread::sleep_for(kFlavorArmSettle);

        ::tc8::stimulus::ArpFrameSpec spec2;
        spec2.opcode = 0x0001;  // Request
        spec2.sender_hw = ::tc8::stimulus::kTesterInjectedMac2;
        spec2.eth_src = ::tc8::stimulus::kTesterInjectedMac2;
        spec2.sender_ip_be = cfg.arp.tester_ip;
        spec2.target_ip_be = cfg.dut.ip;
        ::tc8::stimulus::emitArpFromTester(iface, spec2);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp45NegSM, arp_45_neg)
