#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_reassembly_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_reassembly_13_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4Reassembly13NegSM = ::SCE::Generated::ipv4_reassembly_13_neg::ipv4_reassembly_13_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.4.4.7 IPv4_REASSEMBLY_13's discard guard
// (overlapping_datagram_discarded_by_reassembly_timeout): the DUT reports, with
// a Time Exceeded code 1 quoting frag 0, that it discarded the datagram.
// Neither reference DUT resolves the overlap (docs/tech-debt.md TD-33), so this
// variant sends the datagram without it and kIpv4FaultDropLastFragment swallows
// the tail; lwIP's bucket expires and lwIP sends the report itself. lwIP-only
// (kCapIngressFault).
template <>
struct TestCaseTraits<cases::Ipv4Reassembly13NegSM>
    : Ipv4ReassemblyFaultNegBase<cases::Ipv4Reassembly13NegSM, ::tc8::sce::kCapIngressFault> {
    static constexpr std::string_view kCaseId      = "IPv4_REASSEMBLY_13_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of IPv4_REASSEMBLY_13: the lwIP kIpv4FaultDropLastFragment ingress "
        "flavor loses the last fragment, so the DUT reports the reassembly expiry; a "
        "conformant DUT reassembles the contiguous datagram and replies";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kIpv4FaultDropLastFragment);
        ::tc8::sce::ipv4::reassembly::emitReassembly13WithoutOverlap(cfg, iface);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Reassembly13NegSM, ipv4_reassembly_13_neg)
