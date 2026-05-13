#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "icmpv4_type_09_sm.h"

namespace tc8::sce::cases {

using Icmpv4Type09SM = ::SCE::Generated::icmpv4_type_09::icmpv4_type_09;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Icmpv4Type09SM>
    : Icmpv4TypedBase<cases::Icmpv4Type09SM, std::uint8_t{0}> {
    static constexpr std::string_view kCaseId      = "ICMPv4_TYPE_09";
    static constexpr std::string_view kSpecSection = "4.3.3.2";
    static constexpr std::string_view kDescription =
        "ICMP Echo Reply identifier and sequence number are echoed from "
        "the Echo Request";

    // Canonical Echo Request — helper seeds echo_id=kIcmpEchoId and
    // echo_seq=kIcmpEchoSeq so the DUT's Echo Reply carries the two
    // values the SCXML guard asserts against `expected.echo_id/seq`
    // (CLI-injected via `--expect icmpv4.echo_id/seq`).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::icmpv4::emitStimulus(cfg, iface);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                 return "pass";
            case State::Fail_echo_id:         return "fail:echo_id_mismatch";
            case State::Fail_echo_seq:        return "fail:echo_seq_mismatch";
            case State::Fail_timeout:         return "fail:no_echo_reply_within_listen_window";
            default:                          return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Icmpv4Type09SM, icmpv4_type_09)
