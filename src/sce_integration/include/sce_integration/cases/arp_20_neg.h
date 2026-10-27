#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_ignore_request_neg.h"
#include "sce_integration/cases/arp_20.h"  // SSOT for the Request the fault swallows
#include "sce_integration/test_runner.h"

#include "arp_20_neg_sm.h"

namespace tc8::sce::cases {

using Arp20NegSM = ::SCE::Generated::arp_20_neg::arp_20_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp20NegSM>
    : ArpIngressFaultNegBase<cases::Arp20NegSM> {
    // Reads ARP_20's requirements (CaseRegistry::requirementsUnderTest), so it is
    // anchored by the same ICMP Echo, which this fault leaves answerable.
    static void stimulus(Captured &c, const ::tc8::TestConfig &cfg, ::tc8::sce::StimulusContext &ctx) {
        emitPositiveRequestUnderIgnoreFault<cases::Arp20SM>(c, cfg, ctx);
    }
    static constexpr std::string_view kCaseId      = "ARP_20_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_20: the lwIP kArpFaultIgnoreWellFormedRequest ingress "
        "flavor swallows a well-formed Request (Hardware Type Ethernet) the DUT must "
        "answer; a conformant DUT replies";
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp20NegSM, arp_20_neg)
