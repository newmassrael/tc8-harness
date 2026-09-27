#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_fragments_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_fragments_01_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4Fragments01NegSM = ::SCE::Generated::ipv4_fragments_01_neg::ipv4_fragments_01_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.4.4.6 IPv4_FRAGMENTS_01's discard guard
// (complete_fragment_pair_discarded_by_reassembly_timeout): the DUT reports, with a
// Time Exceeded code 1 quoting frag 0, that it discarded the datagram. Neither
// reference DUT discards the pair, so no positive run reaches the guard
// (docs/tech-debt.md TD-41); kIpv4FaultDropLastFragment swallows the tail, so
// lwIP's bucket expires and lwIP sends the report itself. The stimulus is the
// positive's own: emitFragmentPair's default parameters ARE FRAGMENTS_01's tuple.
// lwIP-only (kCapIngressFault).
template <>
struct TestCaseTraits<cases::Ipv4Fragments01NegSM>
    : Ipv4ReassemblyFaultNegBase<cases::Ipv4Fragments01NegSM, ::tc8::sce::kCapIngressFault> {
    static constexpr std::string_view kCaseId      = "IPv4_FRAGMENTS_01_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of IPv4_FRAGMENTS_01: the lwIP kIpv4FaultDropLastFragment ingress "
        "flavor loses the tail fragment, so the DUT reports the reassembly expiry; a "
        "conformant DUT reassembles the pair and replies";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        emitIngressFlavorArm(cfg, ctx.iface, ::tc8::ut::kIpv4FaultDropLastFragment);
        ::tc8::sce::ipv4::fragments::emitFragmentPair(
            ctx.iface, cfg, cfg.arp.dut_iface_mac, ::tc8::sce::ipv4::fragments::FragmentPairParams{});
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Fragments01NegSM, ipv4_fragments_01_neg)
