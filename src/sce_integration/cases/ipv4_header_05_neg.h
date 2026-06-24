#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/cases/ipv4_header_05.h"
#include "sce_integration/test_runner.h"

#include "ipv4_header_05_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4Header05NegSM = ::SCE::Generated::ipv4_header_05_neg::ipv4_header_05_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Header05NegSM>
    : Icmpv4EgressFaultNegBase<cases::Ipv4Header05NegSM> {
    static constexpr std::string_view kCaseId      = "IPv4_HEADER_05_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of IPv4_HEADER_05: the lwIP kIcmpFaultEchoPayloadByteWrong egress "
        "flavor corrupts the first Echo Data byte; a conformant DUT echoes the 548 B verbatim";

    // Arm the payload-byte fault, then send the same 576-octet Echo Request the positive
    // uses (shared emitHeader05Stimulus SSOT). The flavor flips the first Echo Data byte
    // (type 0 + payload length intact, so the filter selects the reply and the mismatch —
    // not truncation — half fires). Proves the positive's payload_mismatch fail-final
    // reachable.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kIcmpFaultEchoPayloadByteWrong);
        ::tc8::sce::cases::emitHeader05Stimulus(cfg, iface);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Header05NegSM, ipv4_header_05_neg)
