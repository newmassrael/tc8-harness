#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_header_02_sm.h"

namespace tc8::sce::cases {

using Ipv4Header02SM = ::SCE::Generated::ipv4_header_02::ipv4_header_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Header02SM>
    : Ipv4ObservationBase<cases::Ipv4Header02SM> {
    static constexpr std::string_view kCaseId      = "IPV4_HEADER_02";
    static constexpr std::string_view kSpecSection = "4.4.4.1";
    static constexpr std::string_view kDescription =
        "DUT silently discards an IPv4 packet whose Header Length "
        "field indicates a value less than 20 bytes";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::ipv4::StimulusOverrides ov{};
        ov.ihl = std::uint8_t{4};  // < 5 words → header-length < 20 bytes
        ::tc8::sce::ipv4::emitStimulus(cfg, iface, ov);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:              return "pass";
            case State::Fail_dut_replied:  return "fail:dut_replied_despite_ihl_lt_5";
            default:                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Header02SM, ipv4_header_02)
