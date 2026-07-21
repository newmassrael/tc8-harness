#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "icmpv4_type_10_neg_sm.h"

namespace tc8::sce::cases {

using Icmpv4Type10NegSM = ::SCE::Generated::icmpv4_type_10_neg::icmpv4_type_10_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Icmpv4Type10NegSM>
    : Icmpv4IngressFaultNegBase<cases::Icmpv4Type10NegSM, std::uint8_t{0}> {
    static constexpr std::string_view kCaseId      = "ICMPv4_TYPE_10_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ICMPv4_TYPE_10: the lwIP kIcmpFaultSynthEchoReply ingress "
        "flavor makes the DUT reply to a bad-checksum Echo Request with an Echo Reply; "
        "a conformant DUT drops it and stays silent";

    // Arm the Echo-Reply synthesis fault, then send the same corrupt-checksum Echo
    // Request the positive uses (the frame the DUT must drop without replying).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kIcmpFaultSynthEchoReply);
        ::tc8::sce::icmpv4::StimulusOverrides ov{};
        ov.corrupt_icmp_checksum = true;
        ::tc8::sce::icmpv4::emitStimulus(cfg, iface, ov);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Icmpv4Type10NegSM, icmpv4_type_10_neg)
