#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_header_01_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4Header01NegSM = ::SCE::Generated::ipv4_header_01_neg::ipv4_header_01_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Header01NegSM>
    : Ipv4EgressFaultNegBase<cases::Ipv4Header01NegSM> {
    static constexpr std::string_view kCaseId      = "IPv4_HEADER_01_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of IPv4_HEADER_01: the lwIP kIpv4FaultTotalLenWrong egress flavor "
        "writes a sub-20 total_length into the Echo Reply IPv4 header; a conformant DUT "
        "emits at least the RFC 791 minimum";

    // Arm the total-length fault, then send the same Echo Request the positive uses. The
    // flavor writes a sub-RFC-791-minimum total_length into the DUT Echo Reply's IPv4
    // header, observed regardless of the (now stale) header checksum.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kIpv4FaultTotalLenWrong);
        ::tc8::sce::ipv4::emitStimulus(cfg, iface);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Header01NegSM, ipv4_header_01_neg)
