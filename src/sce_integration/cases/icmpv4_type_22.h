#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "icmpv4_type_22_sm.h"

namespace tc8::sce::cases {

using Icmpv4Type22SM = ::SCE::Generated::icmpv4_type_22::icmpv4_type_22;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Icmpv4Type22SM>
    : Icmpv4TypedBase<cases::Icmpv4Type22SM, std::uint8_t{0}> {
    static constexpr std::string_view kCaseId      = "ICMPV4_TYPE_22";
    static constexpr std::string_view kSpecSection = "4.3.3.2";
    static constexpr std::string_view kDescription =
        "DUT responds to an ICMP Echo Request by sending an ICMP Echo "
        "Reply (RFC 792 MUST)";

    // Canonical Echo Request with no field overrides — the spec row's
    // only assertion is that the DUT emits an Echo Reply, so the
    // stimulus stays at the pilot default.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::icmpv4::emitStimulus(cfg, iface);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:            return "pass";
            case State::Fail_timeout:    return "fail:no_echo_reply_within_listen_window";
            default:                     return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Icmpv4Type22SM, icmpv4_type_22)
