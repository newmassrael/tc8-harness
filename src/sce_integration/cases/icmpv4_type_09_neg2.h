#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "icmpv4_type_09_neg2_sm.h"

namespace tc8::sce::cases {

using Icmpv4Type09Neg2SM = ::SCE::Generated::icmpv4_type_09_neg2::icmpv4_type_09_neg2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Icmpv4Type09Neg2SM>
    : Icmpv4EgressFaultNegBase<cases::Icmpv4Type09Neg2SM> {
    static constexpr std::string_view kCaseId      = "ICMPv4_TYPE_09_NEG2";
    static constexpr std::string_view kDescription =
        "Self-validation of ICMPv4_TYPE_09: the lwIP kIcmpFaultEchoSeqWrong egress flavor "
        "flips the Echo Reply sequence; a conformant DUT echoes the request sequence";

    // Sequence-iteration sibling of icmpv4_type_09_neg: arm the echo-sequence fault,
    // then send the same canonical Echo Request. The flavor flips the DUT Echo Reply's
    // sequence number (type 0 intact), proving the positive's echo_seq_mismatch
    // fail-final reachable.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kIcmpFaultEchoSeqWrong);
        ::tc8::sce::icmpv4::emitStimulus(cfg, iface);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Icmpv4Type09Neg2SM, icmpv4_type_09_neg2)
