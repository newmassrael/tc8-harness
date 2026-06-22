#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_ttl_01_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4Ttl01NegSM = ::SCE::Generated::ipv4_ttl_01_neg::ipv4_ttl_01_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Ttl01NegSM>
    : Ipv4EgressFaultNegBase<cases::Ipv4Ttl01NegSM> {
    static constexpr std::string_view kCaseId      = "IPv4_TTL_01_NEG";
    static constexpr std::string_view kSpecSection = "4.4.4.3";
    static constexpr std::string_view kDescription =
        "Self-validation of IPv4_TTL_01: the lwIP kIpv4FaultTtlZero egress flavor zeroes "
        "the Echo Reply IPv4 TTL; a conformant DUT emits a non-zero TTL";

    // Arm the TTL-zero fault, then send the same Echo Request the positive uses. The
    // flavor zeroes the DUT Echo Reply's IPv4 TTL — the RFC 1122 section 3.2.1.7
    // violation the positive forbids — observed regardless of the (now stale) IPv4
    // header checksum.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kIpv4FaultTtlZero);
        ::tc8::sce::ipv4::emitStimulus(cfg, iface);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Ttl01NegSM, ipv4_ttl_01_neg)
