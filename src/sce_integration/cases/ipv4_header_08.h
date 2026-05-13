#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_header_08_sm.h"

namespace tc8::sce::cases {

using Ipv4Header08SM = ::SCE::Generated::ipv4_header_08::ipv4_header_08;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Header08SM>
    : Ipv4ObservationBase<cases::Ipv4Header08SM> {
    static constexpr std::string_view kCaseId      = "IPv4_HEADER_08";
    static constexpr std::string_view kSpecSection = "4.4.4.1";
    static constexpr std::string_view kDescription =
        "DUT discards a packet whose Total Length is smaller than the "
        "header length implied by IHL (spec literal: IHL=13)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::ipv4::StimulusOverrides ov{};
        // Spec §4.4.4.1 p529: "IP IHL field set to 13". With tot_len at
        // the default 28, kernel computes ihl*4=52 > tot_len and drops.
        ov.ihl = std::uint8_t{13};
        ::tc8::sce::ipv4::emitStimulus(cfg, iface, ov);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:              return "pass";
            case State::Fail_dut_replied:  return "fail:dut_replied_despite_ihl_times_4_gt_tot_len";
            default:                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Header08SM, ipv4_header_08)
