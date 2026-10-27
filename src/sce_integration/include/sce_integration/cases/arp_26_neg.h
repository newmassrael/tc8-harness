#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_ignore_request_neg.h"
#include "sce_integration/cases/arp_26.h"  // SSOT for the Request the fault swallows
#include "sce_integration/test_runner.h"

#include "arp_26_neg_sm.h"

namespace tc8::sce::cases {

using Arp26NegSM = ::SCE::Generated::arp_26_neg::arp_26_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp26NegSM>
    : ArpIngressFaultNegBase<cases::Arp26NegSM> {
    // As ARP_20_NEG: ARP_26's requirements, the same Echo anchor.
    static void stimulus(Captured &c, const ::tc8::TestConfig &cfg, ::tc8::sce::StimulusContext &ctx) {
        emitPositiveRequestUnderIgnoreFault<cases::Arp26SM>(c, cfg, ctx);
    }
    static constexpr std::string_view kCaseId      = "ARP_26_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_26: the lwIP kArpFaultIgnoreWellFormedRequest ingress "
        "flavor swallows a well-formed Request (Protocol Type IPv4) the DUT must "
        "answer; a conformant DUT replies";
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp26NegSM, arp_26_neg)
