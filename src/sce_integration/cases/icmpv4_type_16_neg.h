#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "icmpv4_type_16_neg_sm.h"

namespace tc8::sce::cases {

using Icmpv4Type16NegSM = ::SCE::Generated::icmpv4_type_16_neg::icmpv4_type_16_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Icmpv4Type16NegSM>
    : Icmpv4IngressFaultNegBase<cases::Icmpv4Type16NegSM, std::uint8_t{16}> {
    static constexpr std::string_view kCaseId      = "ICMPv4_TYPE_16_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ICMPv4_TYPE_16: the lwIP kIcmpFaultSynthInfoReply ingress "
        "flavor makes the DUT answer an Information Request with the prohibited "
        "Information Reply; a conformant DUT stays silent";

    // Arm the Info-Reply synthesis fault, then send the same Information Request
    // (type=15) the positive uses (the frame the DUT must not answer).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kIcmpFaultSynthInfoReply);
        ::tc8::sce::icmpv4::StimulusOverrides ov{};
        ov.icmp_type = std::uint8_t{15};  // Information Request
        ov.icmp_code = std::uint8_t{0};
        ::tc8::sce::icmpv4::emitStimulus(cfg, iface, ov);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Icmpv4Type16NegSM, icmpv4_type_16_neg)
