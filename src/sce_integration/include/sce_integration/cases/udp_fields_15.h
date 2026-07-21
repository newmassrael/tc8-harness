#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_fields_15_sm.h"

namespace tc8::sce::cases {

using UdpFields15SM = ::SCE::Generated::udp_fields_15::udp_fields_15;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpFields15SM>
    : UdpAnyBase<cases::UdpFields15SM> {
    static constexpr std::string_view kCaseId      = "UDP_FIELDS_15";
    static constexpr std::string_view kDescription =
        "DUT silently discards a UDP datagram with non-zero invalid "
        "checksum (RFC 1122 §4.1.3.4 MUST)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::udp::UdpStimulusOverrides ov{};
        // Deliberately-wrong checksum value disjoint from any plausible
        // RFC 1071 sum over the (tester, DUT) pseudo-header / 8 B
        // payload region.
        ov.udp.checksum_field = std::uint16_t{0xDEAD};
        ::tc8::sce::udp::emitIngressProbeAndQuery(
            cfg, iface, cfg.dut.mac,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            ::tc8::sce::udp::kUdpDefaultData.size(),
            ::tc8::sce::udp::kDataPeerPort, ov);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpFields15SM, udp_fields_15)
