#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "icmpv4_error_05_sm.h"

namespace tc8::sce::cases {

using Icmpv4Error05SM = ::SCE::Generated::icmpv4_error_05::icmpv4_error_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Icmpv4Error05SM>
    : Icmpv4AnyBase<cases::Icmpv4Error05SM> {
    static constexpr std::string_view kCaseId      = "ICMPv4_ERROR_05";
    static constexpr std::string_view kSpecSection = "4.3.3.1";
    static constexpr std::string_view kDescription =
        "DUT silently discards an ICMP message of unknown type (RFC 1122 "
        "§3.2.2 MUST)";

    // Send an ICMP message with a type the DUT's kernel has no handler
    // for. 202 is unassigned by IANA (ICMP type registry) and has no
    // Linux dispatch entry — the kernel drops it in `icmp_rcv` via the
    // default branch. The 8-byte header layout is preserved (builder
    // treats it like any Echo-shape header, with id/seq in the rest-
    // of-header slots), so the frame is well-formed at every layer
    // except the unknown type — isolating the MUST-NOT-respond
    // behaviour under test. Code stays at 0 since the message is
    // rejected before code-dispatch.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::icmpv4::StimulusOverrides ov{};
        ov.icmp_type = std::uint8_t{202};
        ov.icmp_code = std::uint8_t{0};
        ::tc8::sce::icmpv4::emitStimulus(cfg, iface, ov);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:              return "pass";
            case State::Fail_dut_replied:  return "fail:dut_sent_icmp_to_unknown_type";
            default:                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Icmpv4Error05SM, icmpv4_error_05)
