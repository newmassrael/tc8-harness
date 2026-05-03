#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_header_09_sm.h"

namespace tc8::sce::cases {

using Ipv4Header09SM = ::SCE::Generated::ipv4_header_09::ipv4_header_09;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Header09SM>
    : Ipv4ObservationBase<cases::Ipv4Header09SM> {
    static constexpr std::string_view kCaseId      = "IPV4_HEADER_09";
    static constexpr std::string_view kSpecSection = "4.4.4.1";
    static constexpr std::string_view kDescription =
        "DUT discards a packet whose Total Length is bigger than the "
        "actual transmitted data (spec literal: Total Length = 48)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::ipv4::StimulusOverrides ov{};
        // Spec §4.4.4.1 p558: "IP Total Length field set to 48". Actual
        // on-wire L3 payload is 28 bytes; kernel detects skb->len <
        // iph->tot_len in ip_rcv_core and drops.
        ov.total_length = std::uint16_t{48};
        ::tc8::sce::ipv4::emitStimulus(cfg, iface, ov);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:              return "pass";
            case State::Fail_dut_replied:  return "fail:dut_replied_despite_tot_len_gt_actual";
            default:                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Header09SM, ipv4_header_09)
