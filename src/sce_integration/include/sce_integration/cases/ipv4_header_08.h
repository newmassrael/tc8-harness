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

// §4.4.4.1 p529 spec literal "IP IHL field set to 13": with tot_len at the
// default 28, ihl*4 = 52 > tot_len, so a conformant DUT drops the datagram and
// stays silent. SSOT shared by the positive stimulus and the IPv4_HEADER_08_NEG
// self-validation (which arms the lwIP synth flavor against the same trigger).
inline constexpr std::uint8_t kIpv4Header08BadIhl = 13U;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Header08SM>
    : Ipv4ObservationBase<cases::Ipv4Header08SM> {
    static constexpr std::string_view kCaseId      = "IPv4_HEADER_08";
    static constexpr std::string_view kDescription =
        "DUT discards a packet whose Total Length is smaller than the "
        "header length implied by IHL (spec literal: IHL=13)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::ipv4::StimulusOverrides ov{};
        ov.ihl = cases::kIpv4Header08BadIhl;
        ::tc8::sce::ipv4::emitStimulus(cfg, iface, ov);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Header08SM, ipv4_header_08)
