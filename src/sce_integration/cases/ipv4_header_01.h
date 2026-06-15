#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_header_01_sm.h"

namespace tc8::sce::cases {

using Ipv4Header01SM = ::SCE::Generated::ipv4_header_01::ipv4_header_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Header01SM>
    : Ipv4ObservationBase<cases::Ipv4Header01SM> {
    static constexpr std::string_view kCaseId      = "IPv4_HEADER_01";
    static constexpr std::string_view kSpecSection = "4.4.4.1";
    static constexpr std::string_view kDescription =
        "DUT's ICMP Echo Reply carries an IPv4 header with Total Length "
        ">= 20 bytes (RFC 791 minimum)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::ipv4::emitStimulus(cfg, iface);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Header01SM, ipv4_header_01)
