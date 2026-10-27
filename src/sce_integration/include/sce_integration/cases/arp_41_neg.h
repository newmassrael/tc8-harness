#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_ignore_request_neg.h"
#include "sce_integration/cases/arp_41.h"  // SSOT for the Request the fault swallows
#include "sce_integration/test_runner.h"

#include "arp_41_neg_sm.h"

namespace tc8::sce::cases {

using Arp41NegSM = ::SCE::Generated::arp_41_neg::arp_41_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp41NegSM>
    : ArpIngressFaultNegBase<cases::Arp41NegSM> {
    // As ARP_20_NEG: ARP_41's requirements, the same Echo anchor.
    static void stimulus(Captured &c, const ::tc8::TestConfig &cfg, ::tc8::sce::StimulusContext &ctx) {
        emitPositiveRequestUnderIgnoreFault<cases::Arp41SM>(c, cfg, ctx);
    }
    static constexpr std::string_view kCaseId      = "ARP_41_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_41: the lwIP kArpFaultIgnoreWellFormedRequest ingress "
        "flavor swallows a well-formed Request the DUT must answer with a Response; "
        "a conformant DUT replies";
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp41NegSM, arp_41_neg)
