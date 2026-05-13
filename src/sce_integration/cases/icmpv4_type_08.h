#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "icmpv4_type_08_sm.h"

namespace tc8::sce::cases {

using Icmpv4Type08SM = ::SCE::Generated::icmpv4_type_08::icmpv4_type_08;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Icmpv4Type08SM>
    : Icmpv4TypedBase<cases::Icmpv4Type08SM, std::uint8_t{0}> {
    static constexpr std::string_view kCaseId      = "ICMPv4_TYPE_08";
    static constexpr std::string_view kSpecSection = "4.3.3.2";
    static constexpr std::string_view kDescription =
        "ICMP Echo Reply data field — DUT reply payload equals the "
        "Echo Request payload sent by the tester";

    // Send an Echo Request carrying the spec literal "ECU NETWORK
    // VALIDATION TEST" (27 bytes). Both the stimulus and the SCXML
    // guard reference `kIcmpv4EchoPayloadType08` so the two sides
    // cannot drift.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::icmpv4::StimulusOverrides ov{};
        ov.payload_data = reinterpret_cast<const std::uint8_t *>(::tc8::kIcmpv4EchoPayloadType08.data());
        ov.payload_len  = static_cast<std::uint32_t>(::tc8::kIcmpv4EchoPayloadType08.size());
        ::tc8::sce::icmpv4::emitStimulus(cfg, iface, ov);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                    return "pass";
            case State::Fail_payload_mismatch:   return "fail:echo_payload_not_returned_verbatim";
            case State::Fail_timeout:            return "fail:no_echo_reply_within_listen_window";
            default:                             return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Icmpv4Type08SM, icmpv4_type_08)
