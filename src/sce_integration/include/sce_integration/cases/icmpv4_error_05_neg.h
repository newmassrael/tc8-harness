#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "icmpv4_error_05_neg_sm.h"

namespace tc8::sce::cases {

using Icmpv4Error05NegSM = ::SCE::Generated::icmpv4_error_05_neg::icmpv4_error_05_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Icmpv4Error05NegSM>
    : Icmpv4IngressFaultNegAnyBase<cases::Icmpv4Error05NegSM> {
    static constexpr std::string_view kCaseId      = "ICMPv4_ERROR_05_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ICMPv4_ERROR_05: the lwIP kIcmpFaultSynthEchoReply ingress "
        "flavor makes the DUT reply to an unknown ICMP type with an Echo Reply; a "
        "conformant DUT silently discards it";

    // Arm the Echo-Reply synthesis fault, then send the same unknown-type (202) ICMP
    // message the positive uses (the frame the DUT must silently discard). The type-
    // agnostic base's src_ip filter excludes the tester's own type-202 stimulus, so only
    // the DUT-origin synthesized reply trips the guard.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kIcmpFaultSynthEchoReply);
        ::tc8::sce::icmpv4::StimulusOverrides ov{};
        ov.icmp_type = std::uint8_t{202};
        ov.icmp_code = std::uint8_t{0};
        ::tc8::sce::icmpv4::emitStimulus(cfg, iface, ov);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Icmpv4Error05NegSM, icmpv4_error_05_neg)
