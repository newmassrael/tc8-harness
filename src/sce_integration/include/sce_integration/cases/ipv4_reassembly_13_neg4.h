#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_reassembly_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_reassembly_13_neg4_sm.h"

namespace tc8::sce::cases {

using Ipv4Reassembly13Neg4SM = ::SCE::Generated::ipv4_reassembly_13_neg4::ipv4_reassembly_13_neg4;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.4.4.7 IPv4_REASSEMBLY_13's data guard
// (reassembled_echo_data_mismatch_overlap). kIcmpFaultEchoPayloadByteWrong
// flips the first Data octet of the Echo Reply lwIP sends for the reassembled
// contiguous datagram. lwIP-only (kCapEgressFault).
template <>
struct TestCaseTraits<cases::Ipv4Reassembly13Neg4SM>
    : Ipv4ReassemblyFaultNegBase<cases::Ipv4Reassembly13Neg4SM, ::tc8::sce::kCapEgressFault> {
    static constexpr std::string_view kCaseId      = "IPv4_REASSEMBLY_13_NEG4";
    static constexpr std::string_view kDescription =
        "Self-validation of IPv4_REASSEMBLY_13: the lwIP kIcmpFaultEchoPayloadByteWrong egress "
        "flavor corrupts the reassembled Echo Reply's data; a conformant DUT echoes it verbatim";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kIcmpFaultEchoPayloadByteWrong);
        ::tc8::sce::ipv4::reassembly::emitReassembly13WithoutOverlap(cfg, iface);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Reassembly13Neg4SM, ipv4_reassembly_13_neg4)
