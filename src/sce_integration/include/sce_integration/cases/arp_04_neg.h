#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_04_neg_sm.h"

namespace tc8::sce::cases {

using Arp04NegSM = ::SCE::Generated::arp_04_neg::arp_04_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp04NegSM>
    : ArpIngressFaultNegProvokedBase<cases::Arp04NegSM> {
    static constexpr std::string_view kCaseId      = "ARP_04_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_04: the lwIP kArpFaultIgnoreLearn ingress flavor "
        "swallows the teaching ARP Request, so the DUT holds no entry and emits "
        "its own Request; a conformant DUT resolves from the cache it was taught";
    // The positive's stimulus, unchanged, with the flavor armed FIRST so the hook
    // is live before the teaching Request arrives — arming after it would let the
    // teaching land and the fault would read as inert.
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg,
                         ::tc8::sce::StimulusContext &ctx) {
        emitIngressFlavorArm(cfg, ctx.iface, ::tc8::ut::kArpFaultIgnoreLearn);
        ::tc8::stimulus::emitArpLearningBoot(ctx.iface, cfg.arp.tester_ip, cfg.dut.ip,
                                             ::tc8::stimulus::ArpLearningVariant::Request);
        emitArpEgressProvocation(ctx.dut, cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp04NegSM, arp_04_neg)
