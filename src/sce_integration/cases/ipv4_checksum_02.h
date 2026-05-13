#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_checksum_02_sm.h"

namespace tc8::sce::cases {

using Ipv4Checksum02SM = ::SCE::Generated::ipv4_checksum_02::ipv4_checksum_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Checksum02SM>
    : Ipv4ObservationBase<cases::Ipv4Checksum02SM> {
    static constexpr std::string_view kCaseId      = "IPv4_CHECKSUM_02";
    static constexpr std::string_view kSpecSection = "4.4.4.2";
    static constexpr std::string_view kDescription =
        "DUT discards an IPv4 packet whose header checksum does not "
        "match the RFC 1071 one's-complement sum of the header words";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::ipv4::StimulusOverrides ov{};
        ov.corrupt_ip_checksum = true;
        ::tc8::sce::ipv4::emitStimulus(cfg, iface, ov);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:              return "pass";
            case State::Fail_dut_replied:  return "fail:dut_replied_despite_invalid_header_checksum";
            default:                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Checksum02SM, ipv4_checksum_02)
