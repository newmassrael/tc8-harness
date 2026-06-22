#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "icmpv4_error_04_neg_sm.h"

namespace tc8::sce::cases {

using Icmpv4Error04NegSM = ::SCE::Generated::icmpv4_error_04_neg::icmpv4_error_04_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Icmpv4Error04NegSM>
    : Icmpv4IngressFaultNegBase<cases::Icmpv4Error04NegSM, std::uint8_t{12}> {
    static constexpr std::string_view kCaseId      = "ICMPv4_ERROR_04_NEG";
    static constexpr std::string_view kSpecSection = "4.3.3.1";
    static constexpr std::string_view kDescription =
        "Self-validation of ICMPv4_ERROR_04: the lwIP kIcmpFaultSynthParamProblem "
        "ingress flavor makes the DUT emit a Parameter Problem in response to a "
        "broadcast datagram with malformed options; a conformant DUT stays silent";

    // Arm the Parameter-Problem synthesis fault, then send the same broadcast Echo
    // Request with a malformed Timestamp option the positive uses (RFC 1122 §3.2.2
    // forbids the Parameter Problem reply because the destination is broadcast).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kIcmpFaultSynthParamProblem);
        ::tc8::sce::icmpv4::StimulusOverrides ov{};
        ov.dst_ip = std::uint32_t{0xFFFFFFFFU};  // 255.255.255.255 (NBO-invariant)
        ov.ip_options.assign(::tc8::stimulus::kIcmpv4TimestampOptionMalformed.begin(),
                             ::tc8::stimulus::kIcmpv4TimestampOptionMalformed.end());
        ::tc8::sce::icmpv4::emitStimulus(cfg, iface, ov);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Icmpv4Error04NegSM, icmpv4_error_04_neg)
