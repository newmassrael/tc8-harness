#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_reassembly_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_reassembly_10_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4Reassembly10NegSM = ::SCE::Generated::ipv4_reassembly_10_neg::ipv4_reassembly_10_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.4.4.7 IPv4_REASSEMBLY_10's phase A discard guard
// (phase_a_datagram_discarded_within_timer). Neither reference DUT discards phase
// A, so no positive run reaches the guard (docs/tech-debt.md TD-41);
// kIpv4FaultDropLastFragment swallows phase A's frag 1, so lwIP's bucket expires
// and lwIP reports it. The stimulus is the positive's phase A alone
// (emitReassembly10PhaseA): phase B exists to expire, so it proves nothing about
// phase A's guard. lwIP-only (kCapIngressFault).
template <>
struct TestCaseTraits<cases::Ipv4Reassembly10NegSM>
    : Ipv4ReassemblyFaultNegBase<cases::Ipv4Reassembly10NegSM, ::tc8::sce::kCapIngressFault> {
    static constexpr std::string_view kCaseId      = "IPv4_REASSEMBLY_10_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of IPv4_REASSEMBLY_10 phase A: the lwIP kIpv4FaultDropLastFragment "
        "ingress flavor loses the tail fragment, so the DUT reports the reassembly expiry; a "
        "conformant DUT reassembles phase A inside the timer and replies";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        emitIngressFlavorArm(cfg, ctx.iface, ::tc8::ut::kIpv4FaultDropLastFragment);
        ::tc8::sce::ipv4::reassembly::emitReassembly10PhaseA(cfg, ctx.iface);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Reassembly10NegSM, ipv4_reassembly_10_neg)
