#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_checksum_05_sm.h"

namespace tc8::sce::cases {

using Ipv4Checksum05SM = ::SCE::Generated::ipv4_checksum_05::ipv4_checksum_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Checksum05SM>
    : Ipv4ObservationBase<cases::Ipv4Checksum05SM> {
    static constexpr std::string_view kCaseId      = "IPV4_CHECKSUM_05";
    static constexpr std::string_view kSpecSection = "4.4.4.2";
    static constexpr std::string_view kDescription =
        "DUT's Echo Reply carries an IPv4 header checksum matching the "
        "RFC 1071 one's-complement sum over the header words";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        // Pilot default — valid checksum, DUT replies, SCXML validates
        // the reply's own checksum via captured.header_checksum_valid().
        ::tc8::sce::ipv4::emitStimulus(cfg, iface);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:          return "pass";
            case State::Fail_checksum: return "fail:dut_reply_header_checksum_invalid";
            case State::Fail_timeout:  return "fail:no_dut_ipv4_packet_within_listen_window";
            default:                   return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Checksum05SM, ipv4_checksum_05)
