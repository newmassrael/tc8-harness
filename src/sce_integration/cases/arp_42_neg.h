#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_42_neg_sm.h"

namespace tc8::sce::cases {

using Arp42NegSM = ::SCE::Generated::arp_42_neg::arp_42_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp42NegSM>
    : ArpIngressFaultNegBase<cases::Arp42NegSM> {
    static constexpr std::string_view kCaseId      = "ARP_42_NEG";
    static constexpr std::string_view kSpecSection = "4.2.4.2";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_42: the lwIP kArpFaultReplyToDropFrame ingress "
        "flavor makes the DUT reply to a frame whose opcode is Response (RFC 826 "
        "requires opcode=Request to reply); a conformant DUT stays silent";
    // Arm the ingress reply fault, then inject the Response the positive uses (a
    // frame the DUT must not reply to).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kArpFaultReplyToDropFrame);
        ::tc8::stimulus::ArpFrameSpec spec;
        spec.opcode = 0x0002;  // Response
        spec.sender_ip_be = cfg.arp.tester_ip;
        spec.target_ip_be = cfg.dut.ip;
        spec.target_hw = cfg.dut.mac;  // addressed to DUT (mirrors positive ARP_42)
        ::tc8::stimulus::emitArpFromTester(iface, spec);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp42NegSM, arp_42_neg)
