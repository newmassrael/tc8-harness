#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_addressing_03_sm.h"

namespace tc8::sce::cases {

using Ipv4Addressing03SM = ::SCE::Generated::ipv4_addressing_03::ipv4_addressing_03;

// 127.0.0.1 in network byte order: bytes 7F 00 00 01, little-endian
// uint32 = 0x0100007F. Loopback target on a non-loopback iface — the
// kernel's martian-source filter drops silently per RFC 1122 section
// 3.2.1.3.
inline constexpr std::uint32_t kIpv4LoopbackBe = 0x0100007FU;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Addressing03SM>
    : Ipv4ObservationBase<cases::Ipv4Addressing03SM> {
    static constexpr std::string_view kCaseId      = "IPv4_ADDRESSING_03";
    static constexpr std::string_view kSpecSection = "4.4.4.5";
    static constexpr std::string_view kDescription =
        "DUT silently discards an IPv4 packet whose Destination Address "
        "is a loopback address (127.0.0.0/8) arriving on a non-loopback "
        "interface";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::ipv4::StimulusOverrides ov{};
        ov.dst_ip = cases::kIpv4LoopbackBe;
        ::tc8::sce::ipv4::emitStimulus(cfg, iface, ov);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Addressing03SM, ipv4_addressing_03)
