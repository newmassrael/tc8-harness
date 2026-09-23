#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_reassembly_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_reassembly_12_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4Reassembly12NegSM = ::SCE::Generated::ipv4_reassembly_12_neg::ipv4_reassembly_12_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.4.4.7 IPv4_REASSEMBLY_12's timer guard
// (reassembly_timer_shrunk_by_low_ttl). Neither reference DUT shrinks its timer
// on a low TTL, so no positive run reaches the guard (docs/tech-debt.md TD-41);
// kIpv4FaultDropLastFragment swallows frag 1, so lwIP's bucket expires and lwIP
// sends the same report a shrinking DUT would. The guard reads only that frame.
// The stimulus is the positive's own (emitReassembly12Pair). lwIP-only
// (kCapIngressFault).
template <>
struct TestCaseTraits<cases::Ipv4Reassembly12NegSM>
    : Ipv4ReassemblyFaultNegBase<cases::Ipv4Reassembly12NegSM, ::tc8::sce::kCapIngressFault> {
    static constexpr std::string_view kCaseId      = "IPv4_REASSEMBLY_12_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of IPv4_REASSEMBLY_12: the lwIP kIpv4FaultDropLastFragment ingress "
        "flavor loses the tail fragment, so the DUT reports the reassembly expiry; a "
        "conformant DUT reassembles the Low-TTL pair and replies";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kIpv4FaultDropLastFragment);
        ::tc8::sce::ipv4::reassembly::emitReassembly12Pair(cfg, iface);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Reassembly12NegSM, ipv4_reassembly_12_neg)
