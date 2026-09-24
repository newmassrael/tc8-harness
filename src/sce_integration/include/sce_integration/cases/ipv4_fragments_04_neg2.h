#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_fragments_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_fragments_04_neg2_sm.h"

namespace tc8::sce::cases {

using Ipv4Fragments04Neg2SM = ::SCE::Generated::ipv4_fragments_04_neg2::ipv4_fragments_04_neg2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.4.4.6 IPv4_FRAGMENTS_04's data guard
// (reassembled_echo_data_mismatch_protocol_case). kIcmpFaultEchoPayloadByteWrong
// corrupts the first Echo Data byte of the Echo Reply lwIP sends for the datagram the
// stimulus completes; the stimulus sends the positive's phase 1 and its phase 2 retry
// back to back. lwIP's reassembly omits the Protocol field from the bucket key, so it
// joins phase 1's pair and the retry completes nothing (the positive's
// platform_known_fail); the one reply it sends is the same datagram, and the guard
// reads only the reply frame. lwIP-only (kCapEgressFault).
template <>
struct TestCaseTraits<cases::Ipv4Fragments04Neg2SM>
    : Ipv4ReassemblyFaultNegBase<cases::Ipv4Fragments04Neg2SM, ::tc8::sce::kCapEgressFault> {
    static constexpr std::string_view kCaseId      = "IPv4_FRAGMENTS_04_NEG2";
    static constexpr std::string_view kDescription =
        "Self-validation of IPv4_FRAGMENTS_04: the lwIP kIcmpFaultEchoPayloadByteWrong egress "
        "flavor corrupts the reassembled Echo Reply's first Echo Data byte; a conformant DUT "
        "echoes it";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kIcmpFaultEchoPayloadByteWrong);
        ::tc8::sce::ipv4::fragments::emitCompoundPhase1ThenRetry(
            iface, cfg, ::tc8::sce::ipv4::fragments::fragments04Phase1());
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Fragments04Neg2SM, ipv4_fragments_04_neg2)
