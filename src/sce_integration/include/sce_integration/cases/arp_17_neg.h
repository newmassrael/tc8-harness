#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_ignore_request_neg.h"
#include "sce_integration/cases/arp_17.h"  // SSOT for the Request the fault swallows
#include "sce_integration/test_runner.h"

#include "arp_17_neg_sm.h"

namespace tc8::sce::cases {

using Arp17NegSM = ::SCE::Generated::arp_17_neg::arp_17_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp17NegSM>
    : ArpIngressFaultNegBase<cases::Arp17NegSM> {
    // As ARP_20_NEG: ARP_17's requirements, the same Echo anchor.
    static void stimulus(Captured &c, const ::tc8::TestConfig &cfg, ::tc8::sce::StimulusContext &ctx) {
        emitPositiveRequestUnderIgnoreFault<cases::Arp17SM>(c, cfg, ctx);
    }
    static constexpr std::string_view kCaseId      = "ARP_17_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_17: the lwIP kArpFaultIgnoreWellFormedRequest ingress "
        "flavor swallows a Request with a broadcast Target Hardware Address the DUT "
        "must answer; a conformant DUT replies";
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp17NegSM, arp_17_neg)
