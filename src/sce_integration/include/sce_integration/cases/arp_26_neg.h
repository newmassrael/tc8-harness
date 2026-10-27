#pragma once

#include <string_view>

#include "tc8/upper_tester_fault_catalog.h"
#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_26_neg_sm.h"

namespace tc8::sce::cases {

using Arp26NegSM = ::SCE::Generated::arp_26_neg::arp_26_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// As ARP_20_NEG: reads ARP_26's requirements, so it is anchored by the same Echo.
template <>
struct TestCaseTraits<cases::Arp26NegSM>
    : ArpIngressFaultNegBase<cases::Arp26NegSM> {
    static constexpr std::string_view kCaseId      = "ARP_26_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_26: the lwIP kArpFaultIgnoreWellFormedRequest ingress "
        "flavor swallows a well-formed Request (Protocol Type IPv4) the DUT must "
        "answer; a conformant DUT replies";
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        emitIngressFlavorArm(cfg, ctx.iface, ::tc8::ut::kArpFaultIgnoreWellFormedRequest);
        ::tc8::stimulus::ArpFrameSpec spec;
        spec.sender_ip_be = cfg.arp.tester_ip;
        spec.target_ip_be = cfg.dut.ip;
        spec.proto_type = 0x0800;  // ARP_PROTOCOL_IP
        ::tc8::stimulus::emitArpFromTester(ctx.iface, spec);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp26NegSM, arp_26_neg)
