#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_reassembly_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_reassembly_04_neg2_sm.h"

namespace tc8::sce::cases {

using Ipv4Reassembly04Neg2SM = ::SCE::Generated::ipv4_reassembly_04_neg2::ipv4_reassembly_04_neg2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.4.4.7 IPv4_REASSEMBLY_04's echo_seq guard
// (echo_seq_mismatch_after_unordered_reassembly). kIcmpFaultEchoSeqWrong corrupts the
// sequence number of the Echo Reply lwIP sends for the datagram the stimulus completes;
// the stimulus sends the positive's four fragments in its out-of-order wire order.
// lwIP-only (kCapEgressFault).
template <>
struct TestCaseTraits<cases::Ipv4Reassembly04Neg2SM>
    : Ipv4ReassemblyFaultNegBase<cases::Ipv4Reassembly04Neg2SM, ::tc8::sce::kCapEgressFault> {
    static constexpr std::string_view kCaseId      = "IPv4_REASSEMBLY_04_NEG2";
    static constexpr std::string_view kDescription =
        "Self-validation of IPv4_REASSEMBLY_04: the lwIP kIcmpFaultEchoSeqWrong egress "
        "flavor corrupts the reassembled Echo Reply's sequence number; a conformant DUT "
        "echoes it";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        emitEgressFlavorArm(cfg, ctx.iface, ::tc8::ut::kIcmpFaultEchoSeqWrong);
        ::tc8::sce::ipv4::reassembly::emitReassembly04Fragments(cfg, ctx.iface);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Reassembly04Neg2SM, ipv4_reassembly_04_neg2)
