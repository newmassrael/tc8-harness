#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_fields_16_sm.h"

namespace tc8::sce::cases {

using UdpFields16SM = ::SCE::Generated::udp_fields_16::udp_fields_16;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpFields16SM>
    : UdpAnyBase<cases::UdpFields16SM> {
    static constexpr std::string_view kCaseId      = "UDP_FIELDS_16";
    static constexpr std::string_view kSpecSection = "4.6.5.4";
    static constexpr std::string_view kDescription =
        "DUT accepts a UDP datagram with Checksum field == 0 (RFC 768 "
        "'no checksum computed' sentinel; RFC 1122 §4.1.3.4 SHOULD "
        "default to checksumming on but MUST allow zero-cksum bypass)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::udp::UdpStimulusOverrides ov{};
        // Override the conformantly-computed sum with the literal 0x0000
        // sentinel after compute. RFC 768 declares this signals "no
        // checksum computed"; receivers MAY accept it and Linux
        // (default sysctl) does.
        ov.udp.checksum_field = std::uint16_t{0x0000};
        ::tc8::sce::udp::emitIngressProbeAndQuery(
            cfg, iface, cfg.dut.mac,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            ::tc8::sce::udp::kUdpDefaultData.size(),
            ::tc8::sce::udp::kDataPeerPort, ov);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpFields16SM, udp_fields_16)
