#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_reassembly_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_reassembly_11_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4Reassembly11NegSM = ::SCE::Generated::ipv4_reassembly_11_neg::ipv4_reassembly_11_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.4.4.7 IPv4_REASSEMBLY_11's timer guard
// (reassembly_timer_not_extended_by_large_ttl): the DUT reports, with a Time
// Exceeded code 1 quoting frag 0, that it discarded the datagram. Neither
// reference DUT extends its timer by TTL (docs/tech-debt.md TD-28), so the
// positive's premise is unreachable; this variant produces the same report on a
// DUT that would otherwise reassemble. kIpv4FaultDropLastFragment swallows the
// last fragment, so lwIP's bucket expires and lwIP sends the report itself.
// lwIP-only (kCapIngressFault).
template <>
struct TestCaseTraits<cases::Ipv4Reassembly11NegSM>
    : Ipv4ReassemblyFaultNegBase<cases::Ipv4Reassembly11NegSM, ::tc8::sce::kCapIngressFault> {
    static constexpr std::string_view kCaseId      = "IPv4_REASSEMBLY_11_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of IPv4_REASSEMBLY_11: the lwIP kIpv4FaultDropLastFragment ingress "
        "flavor loses the last fragment, so the DUT reports the reassembly expiry; a "
        "conformant DUT reassembles the back-to-back pair and replies";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        emitIngressFlavorArm(cfg, ctx.iface, ::tc8::ut::kIpv4FaultDropLastFragment);
        ::tc8::sce::ipv4::reassembly::emitReassembly11PairBackToBack(cfg, ctx.iface);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Reassembly11NegSM, ipv4_reassembly_11_neg)
