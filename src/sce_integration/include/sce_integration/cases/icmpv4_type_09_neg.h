#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "icmpv4_type_09_neg_sm.h"

namespace tc8::sce::cases {

using Icmpv4Type09NegSM = ::SCE::Generated::icmpv4_type_09_neg::icmpv4_type_09_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Icmpv4Type09NegSM>
    : Icmpv4EgressFaultNegBase<cases::Icmpv4Type09NegSM> {
    static constexpr std::string_view kCaseId      = "ICMPv4_TYPE_09_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ICMPv4_TYPE_09: the lwIP kIcmpFaultEchoIdWrong egress flavor "
        "flips the Echo Reply identifier; a conformant DUT echoes the request identifier";

    // Arm the echo-identifier fault, then send the same canonical Echo Request the
    // positive uses. The flavor flips the DUT Echo Reply's identifier (type 0 intact, so
    // the filter still selects it) — the violation the positive forbids. Proves the
    // positive's echo_id_mismatch fail-final reachable; the _NEG2 sibling covers
    // echo_seq_mismatch.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kIcmpFaultEchoIdWrong);
        ::tc8::sce::icmpv4::emitStimulus(cfg, iface);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Icmpv4Type09NegSM, icmpv4_type_09_neg)
