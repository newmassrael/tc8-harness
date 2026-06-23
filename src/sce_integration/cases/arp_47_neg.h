#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_47_neg_sm.h"

namespace tc8::sce::cases {

using Arp47NegSM = ::SCE::Generated::arp_47_neg::arp_47_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp47NegSM>
    : ArpEgressFaultNegBase<cases::Arp47NegSM> {
    static constexpr std::string_view kCaseId      = "ARP_47_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_47: the lwIP ArpFaultHwLenWrong egress "
        "flavor corrupts the Hardware Address Length of the DUT's ARP "
        "Reply (RFC 826 Ethernet 6); a conformant DUT emits 6";
    // Arm the egress fault, then send the tester ARP Request the positive
    // uses so the lwIP DUT emits a (corrupted) Reply.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kArpFaultHwLenWrong);
        ::tc8::stimulus::ArpFrameSpec spec;
        spec.sender_ip_be = cfg.arp.tester_ip;
        spec.target_ip_be = cfg.dut.ip;
        ::tc8::stimulus::emitArpFromTester(iface, spec);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp47NegSM, arp_47_neg)
