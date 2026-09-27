#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_fragments_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_fragments_01_neg2_sm.h"

namespace tc8::sce::cases {

using Ipv4Fragments01Neg2SM = ::SCE::Generated::ipv4_fragments_01_neg2::ipv4_fragments_01_neg2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.4.4.6 IPv4_FRAGMENTS_01's echo_seq guard (echo_seq_mismatch).
// kIcmpFaultEchoSeqWrong corrupts the sequence number of the Echo Reply lwIP sends for
// the datagram the stimulus completes; the stimulus sends the positive's fragment pair.
// lwIP-only (kCapEgressFault).
template <>
struct TestCaseTraits<cases::Ipv4Fragments01Neg2SM>
    : Ipv4ReassemblyFaultNegBase<cases::Ipv4Fragments01Neg2SM, ::tc8::sce::kCapEgressFault> {
    static constexpr std::string_view kCaseId      = "IPv4_FRAGMENTS_01_NEG2";
    static constexpr std::string_view kDescription =
        "Self-validation of IPv4_FRAGMENTS_01: the lwIP kIcmpFaultEchoSeqWrong egress "
        "flavor corrupts the reassembled Echo Reply's sequence number; a conformant DUT "
        "echoes it";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        emitEgressFlavorArm(cfg, ctx.iface, ::tc8::ut::kIcmpFaultEchoSeqWrong);
        ::tc8::sce::ipv4::fragments::emitFragmentPair(
            ctx.iface, cfg, cfg.arp.dut_iface_mac, ::tc8::sce::ipv4::fragments::FragmentPairParams{});
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Fragments01Neg2SM, ipv4_fragments_01_neg2)
