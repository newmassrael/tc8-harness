#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_38_neg_sm.h"

namespace tc8::sce::cases {

using Arp38NegSM = ::SCE::Generated::arp_38_neg::arp_38_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp38NegSM>
    : ArpIngressFaultNegUdpBase<cases::Arp38NegSM> {
    static constexpr std::string_view kCaseId      = "ARP_38_NEG";
    static constexpr std::string_view kSpecSection = "4.2.4.2";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_38: the lwIP kArpFaultLearnFromDropFrame ingress "
        "flavor makes the DUT learn a non-gratuitous Response targeting an unused "
        "host it must drop; a conformant DUT emits its own ARP Request";
    // Arm the ingress learn fault, inject the non-gratuitous Response the positive
    // uses (target_ip = unused subnet host 172.16.0.99, the frame the DUT must
    // drop), then provoke UDP egress.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        constexpr std::uint32_t kUnusedTargetIpBe =
            (static_cast<std::uint32_t>(99) << 24) |
            (static_cast<std::uint32_t>(0) << 16) |
            (static_cast<std::uint32_t>(16) << 8) |
            static_cast<std::uint32_t>(172);  // 172.16.0.99 in network byte order
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kArpFaultLearnFromDropFrame);
        ::tc8::stimulus::ArpFrameSpec spec;
        spec.opcode = 0x0002;  // Response (non-gratuitous)
        spec.sender_ip_be = cfg.arp.tester_ip;
        spec.target_ip_be = kUnusedTargetIpBe;
        ::tc8::stimulus::emitArpFromTester(iface, spec);
        // Full provocation wait (mirrors the positive ARP_38): the gap lets the
        // ingress hook land the static entry before the UT-provoked UDP egress.
        emitArpEgressProvocation(cfg, iface, cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp38NegSM, arp_38_neg)
