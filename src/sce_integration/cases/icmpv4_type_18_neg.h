#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "icmpv4_type_18_neg_sm.h"

namespace tc8::sce::cases {

using Icmpv4Type18NegSM = ::SCE::Generated::icmpv4_type_18_neg::icmpv4_type_18_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Icmpv4Type18NegSM>
    : Icmpv4EgressFaultNegBase<cases::Icmpv4Type18NegSM, std::uint8_t{3}> {
    static constexpr std::string_view kCaseId      = "ICMPv4_TYPE_18_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ICMPv4_TYPE_18: the lwIP kIcmpFaultDestUnreachCodeWrong egress "
        "flavor flips the Destination Unreachable code; a conformant DUT emits code 2";

    // Arm the dest-unreach-code fault, then send the same unsupported-protocol packet the
    // positive uses (IPv4 Protocol=253, RFC 3692 experimental) so the DUT replies
    // Destination Unreachable (type 3). The flavor flips the reply's code off 2 (type 3
    // intact, so the filter still selects it) — the violation the positive forbids.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kIcmpFaultDestUnreachCodeWrong);
        ::tc8::sce::icmpv4::StimulusOverrides ov{};
        ov.ip_protocol = std::uint8_t{253};
        ::tc8::sce::icmpv4::emitStimulus(cfg, iface, ov);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Icmpv4Type18NegSM, icmpv4_type_18_neg)
