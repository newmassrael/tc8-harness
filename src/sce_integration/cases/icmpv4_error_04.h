#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "icmpv4_error_04_sm.h"

namespace tc8::sce::cases {

using Icmpv4Error04SM = ::SCE::Generated::icmpv4_error_04::icmpv4_error_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Icmpv4Error04SM>
    : Icmpv4TypedBase<cases::Icmpv4Error04SM, std::uint8_t{12}> {
    static constexpr std::string_view kCaseId      = "ICMPv4_ERROR_04";
    static constexpr std::string_view kSpecSection = "4.3.3.1";
    static constexpr std::string_view kDescription =
        "DUT must not emit an ICMP Parameter Problem message in "
        "response to a datagram whose destination is an IP broadcast "
        "address, even when IP options are malformed (RFC 1122 "
        "§3.2.2 MUST)";

    // Send an ICMP Echo Request to the limited IPv4 broadcast address
    // (255.255.255.255) carrying the malformed Internet Timestamp
    // option (length=10 over 8 B, pointer=9). A conformant DUT
    // detects the parameter problem in the options parse, but the
    // broadcast destination rule (RFC 1122 §3.2.2) prohibits emitting
    // ICMP Parameter Problem (type=12) in reply.
    //
    // IP destination = 255.255.255.255 in network byte order:
    //   inet_pton("255.255.255.255") → 0xFFFFFFFF in NBO, identical
    //   under host byte order since all bytes are 0xFF.
    // Keeping the Ethernet destination at the builder's broadcast
    // default is consistent with the IP-broadcast semantic — a real
    // TESTER sending to 255.255.255.255 uses Eth broadcast too, and
    // Linux's `icmp_send` gate on PACKET_HOST suppresses the
    // Parameter Problem reply as a kernel-side enforcement of the
    // RFC 1122 rule. See `reference_icmp_packet_host_gate.md`.
    //
    // Option bytes single-sourced as `kIcmpv4TimestampOptionMalformed`
    // — shared with TYPE_05. Duplicating the literal here would split
    // the source of truth across cases and break on any future
    // option-encoding change.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::icmpv4::StimulusOverrides ov{};
        ov.dst_ip = std::uint32_t{0xFFFFFFFFU};  // 255.255.255.255 (NBO-invariant)
        ov.ip_options.assign(::tc8::stimulus::kIcmpv4TimestampOptionMalformed.begin(),
                             ::tc8::stimulus::kIcmpv4TimestampOptionMalformed.end());
        ::tc8::sce::icmpv4::emitStimulus(cfg, iface, ov);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:             return "pass";
            case State::Fail_dut_replied: return "fail:dut_sent_parameter_problem_to_broadcast";
            default:                      return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Icmpv4Error04SM, icmpv4_error_04)
