#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_reassembly_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_reassembly_10_neg3_sm.h"

namespace tc8::sce::cases {

using Ipv4Reassembly10Neg3SM = ::SCE::Generated::ipv4_reassembly_10_neg3::ipv4_reassembly_10_neg3;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.4.4.7 IPv4_REASSEMBLY_10's data guard
// (reassembled_echo_data_mismatch_phase_a). kIcmpFaultEchoPayloadByteWrong corrupts the
// first Echo Data byte of the Echo Reply lwIP sends for the datagram the stimulus
// completes; the stimulus sends the positive's phase A pair, inside the reassembly
// timer. lwIP-only (kCapEgressFault).
template <>
struct TestCaseTraits<cases::Ipv4Reassembly10Neg3SM>
    : Ipv4ReassemblyFaultNegBase<cases::Ipv4Reassembly10Neg3SM, ::tc8::sce::kCapEgressFault> {
    static constexpr std::string_view kCaseId      = "IPv4_REASSEMBLY_10_NEG3";
    static constexpr std::string_view kDescription =
        "Self-validation of IPv4_REASSEMBLY_10: the lwIP kIcmpFaultEchoPayloadByteWrong egress "
        "flavor corrupts the reassembled Echo Reply's first Echo Data byte; a conformant DUT "
        "echoes it";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        emitEgressFlavorArm(cfg, ctx.iface, ::tc8::ut::kIcmpFaultEchoPayloadByteWrong);
        ::tc8::sce::ipv4::reassembly::emitReassembly10PhaseA(cfg, ctx.iface);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Reassembly10Neg3SM, ipv4_reassembly_10_neg3)
