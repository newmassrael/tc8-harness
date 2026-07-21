#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_version_03_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4Version03NegSM = ::SCE::Generated::ipv4_version_03_neg::ipv4_version_03_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Version03NegSM>
    : Ipv4EgressFaultNegBase<cases::Ipv4Version03NegSM> {
    static constexpr std::string_view kCaseId      = "IPv4_VERSION_03_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of IPv4_VERSION_03: the lwIP kIpv4FaultVersionWrong egress flavor "
        "forces the Echo Reply IPv4 version nibble to 6; a conformant DUT emits version 4";

    // Arm the version fault, then send the same Echo Request the positive uses. The flavor
    // rewrites the DUT Echo Reply's IPv4 version nibble to 6 (IHL preserved); the pipeline
    // dispatches by L2 ethertype so the frame still reaches the IPv4 guard.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kIpv4FaultVersionWrong);
        ::tc8::sce::ipv4::emitStimulus(cfg, iface);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Version03NegSM, ipv4_version_03_neg)
