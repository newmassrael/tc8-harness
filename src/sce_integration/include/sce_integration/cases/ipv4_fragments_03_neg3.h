#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_fragments_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_fragments_03_neg3_sm.h"

namespace tc8::sce::cases {

using Ipv4Fragments03Neg3SM = ::SCE::Generated::ipv4_fragments_03_neg3::ipv4_fragments_03_neg3;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.4.4.6 IPv4_FRAGMENTS_03's phase-1 guard
// (dut_reassembled_mismatched_src_fragments). kIpv4FaultNormaliseFragTuple rewrites the
// later fragment's SOURCE ADDRESS to the head's at the netif input, so the stack sees a
// matching pair and answers while the wire carried the mismatch. One flavour covers the
// id / source / protocol variants because the tuple is what matching is defined over.
// lwIP-only (kCapIngressFault).
template <>
struct TestCaseTraits<cases::Ipv4Fragments03Neg3SM>
    : Ipv4ReassemblyFaultNegBase<cases::Ipv4Fragments03Neg3SM, ::tc8::sce::kCapIngressFault> {
    static constexpr std::string_view kCaseId      = "IPv4_FRAGMENTS_03_NEG3";
    static constexpr std::string_view kDescription =
        "Self-validation of IPv4_FRAGMENTS_03: the lwIP kIpv4FaultNormaliseFragTuple "
        "ingress flavor makes the DUT reassemble a pair whose source addresses differ "
        "on the wire; a conformant DUT refuses the pair and answers nothing";
    // PHASE 1 ONLY — see the template's header for why the positive's phase-2 matched
    // retry must not be sent here: its reply is conformant, and including it would make
    // any Echo Reply ambiguous and the pass vacuous.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kIpv4FaultNormaliseFragTuple);
        ::tc8::sce::ipv4::fragments::emitFragmentPair(
            iface, cfg, cfg.arp.dut_iface_mac,
            ::tc8::sce::ipv4::fragments::fragments03Phase1());
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Fragments03Neg3SM, ipv4_fragments_03_neg3)
