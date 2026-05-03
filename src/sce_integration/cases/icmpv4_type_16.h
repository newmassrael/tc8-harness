#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "icmpv4_type_16_sm.h"

namespace tc8::sce::cases {

using Icmpv4Type16SM = ::SCE::Generated::icmpv4_type_16::icmpv4_type_16;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Icmpv4Type16SM>
    : Icmpv4TypedBase<cases::Icmpv4Type16SM, std::uint8_t{16}> {
    static constexpr std::string_view kCaseId      = "ICMPV4_TYPE_16";
    static constexpr std::string_view kSpecSection = "4.3.3.2";
    static constexpr std::string_view kDescription =
        "DUT does not respond to an ICMP Information Request with an "
        "Information Reply (RFC 1122 §3.2.2.7 SHOULD NOT)";

    // Send an ICMP Information Request (type=15). The 8-byte ICMP
    // header layout is identical across Echo and Information message
    // types (rest-of-header carries identifier/sequence in both) so
    // the shared builder covers it via `icmp_type_override`. Linux's
    // kernel validates checksum regardless of type, so the resulting
    // frame is well-formed at every layer except the ICMP type
    // semantic — isolating the SHOULD-NOT-reply behaviour under test.
    //
    // Per RFC 792 the spec addressing is network-portion source and
    // zero destination; Linux ignores the message purely by type, so
    // we keep the IPv4 header conformant (valid src/dst, valid
    // checksum) to avoid an upstream IP-layer drop masking the ICMP
    // type ignore we're actually validating.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::icmpv4::StimulusOverrides ov{};
        ov.icmp_type = std::uint8_t{15};  // Information Request
        ov.icmp_code = std::uint8_t{0};
        ::tc8::sce::icmpv4::emitStimulus(cfg, iface, ov);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:              return "pass";
            case State::Fail_dut_replied:  return "fail:dut_sent_information_reply";
            default:                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Icmpv4Type16SM, icmpv4_type_16)
