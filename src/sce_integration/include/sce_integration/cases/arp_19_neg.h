#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_ignore_request_neg.h"
#include "sce_integration/cases/arp_19.h"  // SSOT for the Request the fault swallows
#include "sce_integration/test_runner.h"

#include "arp_19_neg_sm.h"

namespace tc8::sce::cases {

using Arp19NegSM = ::SCE::Generated::arp_19_neg::arp_19_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp19NegSM>
    : ArpIngressFaultNegBase<cases::Arp19NegSM> {
    // As ARP_20_NEG: ARP_19's requirements, the same Echo anchor.
    static void stimulus(Captured &c, const ::tc8::TestConfig &cfg, ::tc8::sce::StimulusContext &ctx) {
        emitPositiveRequestUnderIgnoreFault<cases::Arp19SM>(c, cfg, ctx);
    }
    static constexpr std::string_view kCaseId      = "ARP_19_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_19: the lwIP kArpFaultIgnoreWellFormedRequest ingress "
        "flavor swallows a broadcast-framed Request carrying the DUT's MAC as Target "
        "Hardware Address, which the DUT must answer; a conformant DUT replies";
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp19NegSM, arp_19_neg)
