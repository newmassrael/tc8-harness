#pragma once

#include <string_view>

#include "tc8/upper_tester_fault_catalog.h"
#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_36_neg_sm.h"

namespace tc8::sce::cases {

using Arp36NegSM = ::SCE::Generated::arp_36_neg::arp_36_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// As ARP_20_NEG: reads ARP_36's requirements, so it is anchored by the same Echo.
template <>
struct TestCaseTraits<cases::Arp36NegSM>
    : ArpIngressFaultNegBase<cases::Arp36NegSM> {
    static constexpr std::string_view kCaseId      = "ARP_36_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_36: the lwIP kArpFaultIgnoreWellFormedRequest ingress "
        "flavor swallows a well-formed Request (Target Protocol Address = the DUT's) "
        "the DUT must answer; a conformant DUT replies";
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        emitIngressFlavorArm(cfg, ctx.iface, ::tc8::ut::kArpFaultIgnoreWellFormedRequest);
        ::tc8::stimulus::ArpFrameSpec spec;
        spec.sender_ip_be = cfg.arp.tester_ip;
        spec.target_ip_be = cfg.dut.ip;
        ::tc8::stimulus::emitArpFromTester(ctx.iface, spec);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp36NegSM, arp_36_neg)
