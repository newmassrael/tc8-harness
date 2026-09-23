#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_reassembly_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_reassembly_13_neg2_sm.h"

namespace tc8::sce::cases {

using Ipv4Reassembly13Neg2SM = ::SCE::Generated::ipv4_reassembly_13_neg2::ipv4_reassembly_13_neg2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.4.4.7 IPv4_REASSEMBLY_13's echo_id guard
// (echo_id_mismatch_after_overlap_reassembly). kIcmpFaultEchoIdWrong flips the
// identifier of the Echo Reply lwIP sends for the reassembled contiguous
// datagram. lwIP-only (kCapEgressFault).
template <>
struct TestCaseTraits<cases::Ipv4Reassembly13Neg2SM>
    : Ipv4ReassemblyFaultNegBase<cases::Ipv4Reassembly13Neg2SM, ::tc8::sce::kCapEgressFault> {
    static constexpr std::string_view kCaseId      = "IPv4_REASSEMBLY_13_NEG2";
    static constexpr std::string_view kDescription =
        "Self-validation of IPv4_REASSEMBLY_13: the lwIP kIcmpFaultEchoIdWrong egress flavor "
        "flips the reassembled Echo Reply's identifier; a conformant DUT echoes it";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kIcmpFaultEchoIdWrong);
        ::tc8::sce::ipv4::reassembly::emitReassembly13WithoutOverlap(cfg, iface);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Reassembly13Neg2SM, ipv4_reassembly_13_neg2)
