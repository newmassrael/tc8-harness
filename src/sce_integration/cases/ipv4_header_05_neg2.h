#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/cases/ipv4_header_05.h"
#include "sce_integration/test_runner.h"

#include "ipv4_header_05_neg2_sm.h"

namespace tc8::sce::cases {

using Ipv4Header05Neg2SM = ::SCE::Generated::ipv4_header_05_neg2::ipv4_header_05_neg2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Header05Neg2SM>
    : Icmpv4EgressFaultNegBase<cases::Ipv4Header05Neg2SM> {
    static constexpr std::string_view kCaseId      = "IPv4_HEADER_05_NEG2";
    static constexpr std::string_view kDescription =
        "Self-validation of IPv4_HEADER_05: the lwIP kIcmpFaultEchoPayloadTruncate egress "
        "flavor shrinks the Echo Reply total_length so the data is truncated; a conformant DUT "
        "echoes the full 548 B";

    // Arm the payload-truncate fault, then send the same 576-octet Echo Request the positive
    // uses (shared emitHeader05Stimulus SSOT). The flavor shrinks the Echo Reply's IP
    // total_length so libtins dissects payload_len = 64 != 548 (the truncation half; the _NEG
    // sibling covers the wrong-bytes half). Proves the positive's payload_truncated fail-final
    // reachable.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kIcmpFaultEchoPayloadTruncate);
        ::tc8::sce::cases::emitHeader05Stimulus(cfg, iface);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Header05Neg2SM, ipv4_header_05_neg2)
