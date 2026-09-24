#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_runner.h"
#include "stimulus/icmpv4_builder.h"  // kIcmpTimestampOriginate

#include "icmpv4_type_12_neg_sm.h"

namespace tc8::sce::cases {

using Icmpv4Type12NegSM = ::SCE::Generated::icmpv4_type_12_neg::icmpv4_type_12_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.3.3.2 ICMPv4_TYPE_12's SEQUENCE guard. A synthesis rather than an
// egress corruption because lwIP implements no Timestamp at all, so there is no reply to
// corrupt — the same reason the four kIcmpFaultSynth* flavours exist for their own absent
// reactions. Narrowed to reply type 14 so the fixture's other ICMP traffic cannot satisfy
// the guard. lwIP-only (kCapIngressFault).
template <>
struct TestCaseTraits<cases::Icmpv4Type12NegSM>
    : Icmpv4IngressFaultNegBase<cases::Icmpv4Type12NegSM, std::uint8_t{14}> {
    static constexpr std::string_view kCaseId      = "ICMPv4_TYPE_12_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ICMPv4_TYPE_12's sequence guard: the lwIP "
        "kIcmpFaultSynthTimestampReplyBadSeq ingress flavor answers the Timestamp Request "
        "with a Reply that echoes the identifier but returns the sequence inverted";
    // The positive's stimulus, unchanged: a Timestamp Request carrying the default
    // identifier and sequence. The flavour is armed first so the hook is ready when the
    // request arrives — the synthesized reply leaves on that same delivery.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kIcmpFaultSynthTimestampReplyBadSeq);
        ::tc8::sce::icmpv4::StimulusOverrides ov{};
        ov.icmp_type = static_cast<std::uint8_t>(13);
        ov.timestamp_originate = ::tc8::stimulus::kIcmpTimestampOriginate;
        ::tc8::sce::icmpv4::emitStimulus(cfg, iface, ov);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Icmpv4Type12NegSM, icmpv4_type_12_neg)
