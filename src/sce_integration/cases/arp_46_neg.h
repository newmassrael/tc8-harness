#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_46_neg_sm.h"

namespace tc8::sce::cases {

using Arp46NegSM = ::SCE::Generated::arp_46_neg::arp_46_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp46NegSM>
    : ArpAnyBase<cases::Arp46NegSM> {
    static constexpr std::string_view kCaseId      = "ARP_46_NEG";
    static constexpr std::string_view kSpecSection = "4.2.4.2";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_46: the lwIP ArpFaultHwTypeWrong egress "
        "flavor corrupts the Hardware Type of the DUT's ARP Reply "
        "(RFC 826 Ethernet 0x0001); a conformant DUT emits 0x0001";
    // Arm the egress fault, then send the tester ARP Request the positive
    // uses so the lwIP DUT emits a (corrupted) Reply.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitArpFlavorArm(cfg, iface, ::tc8::ut::kArpFaultHwTypeWrong);
        ::tc8::stimulus::ArpFrameSpec spec;
        spec.sender_ip_be = cfg.arp.tester_ip;
        spec.target_ip_be = cfg.dut.ip;
        ::tc8::stimulus::emitArpFromTester(iface, spec);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp46NegSM, arp_46_neg)
