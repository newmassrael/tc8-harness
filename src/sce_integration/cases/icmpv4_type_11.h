#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_runner.h"
#include "stimulus/icmpv4_builder.h"  // kIcmpTimestampOriginate

#include "icmpv4_type_11_sm.h"

namespace tc8::sce::cases {

using Icmpv4Type11SM = ::SCE::Generated::icmpv4_type_11::icmpv4_type_11;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Icmpv4Type11SM>
    : Icmpv4TypedBase<cases::Icmpv4Type11SM, std::uint8_t{14}> {
    static constexpr std::string_view kCaseId      = "ICMPv4_TYPE_11";
    static constexpr std::string_view kSpecSection = "4.3.3.2";
    static constexpr std::string_view kDescription =
        "ICMP Timestamp Reply echoes Originate Timestamp and fills "
        "Receive / Transmit fields with non-zero clock readings";

    // RFC 792 p17 Timestamp Request (type=13). Originate literal is
    // single-sourced via `kIcmpTimestampOriginate` so the SCXML pass
    // guard's `cpp:` literal references the same constant. Receive /
    // Transmit slots stay at 0 on the wire (RFC 792: the responder
    // fills them); the builder zero-fills by default so no override
    // is needed for those.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::icmpv4::StimulusOverrides ov{};
        ov.icmp_type = static_cast<std::uint8_t>(13);
        ov.timestamp_originate = ::tc8::stimulus::kIcmpTimestampOriginate;
        ::tc8::sce::icmpv4::emitStimulus(cfg, iface, ov);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                  return "pass";
            case State::Fail_zero_receive:     return "fail:timestamp_reply_receive_field_zero";
            case State::Fail_zero_transmit:    return "fail:timestamp_reply_transmit_field_zero";
            case State::Fail_wrong_originate:  return "fail:timestamp_reply_originate_not_echoed";
            case State::Fail_timeout:          return "fail:no_timestamp_reply_within_listen_window";
            default:                           return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Icmpv4Type11SM, icmpv4_type_11)
