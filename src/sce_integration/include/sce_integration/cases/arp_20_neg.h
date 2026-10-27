#pragma once

#include <string_view>

#include "tc8/upper_tester_fault_catalog.h"
#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_20_neg_sm.h"

namespace tc8::sce::cases {

using Arp20NegSM = ::SCE::Generated::arp_20_neg::arp_20_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Declares no kRequirementsUnderTest: as a `_NEG` it reads ARP_20's, so its silence
// is anchored by the same ICMP Echo — which this fault, swallowing only the Requests
// for the DUT's address, leaves answerable (CaseRegistry::requirementsUnderTest).
template <>
struct TestCaseTraits<cases::Arp20NegSM>
    : ArpIngressFaultNegBase<cases::Arp20NegSM> {
    static constexpr std::string_view kCaseId      = "ARP_20_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_20: the lwIP kArpFaultIgnoreWellFormedRequest ingress "
        "flavor swallows a well-formed Request (Hardware Type Ethernet) the DUT must "
        "answer; a conformant DUT replies";
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        emitIngressFlavorArm(cfg, ctx.iface, ::tc8::ut::kArpFaultIgnoreWellFormedRequest);
        ::tc8::stimulus::ArpFrameSpec spec;
        spec.sender_ip_be = cfg.arp.tester_ip;
        spec.target_ip_be = cfg.dut.ip;
        spec.hw_type = 0x0001;  // ARP_HARDWARE_ETHERNET
        ::tc8::stimulus::emitArpFromTester(ctx.iface, spec);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp20NegSM, arp_20_neg)
