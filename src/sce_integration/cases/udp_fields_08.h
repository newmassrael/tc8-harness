#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_fields_08_sm.h"

namespace tc8::sce::cases {

using UdpFields08SM = ::SCE::Generated::udp_fields_08::udp_fields_08;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpFields08SM>
    : UdpAnyBase<cases::UdpFields08SM> {
    static constexpr std::string_view kCaseId      = "UDP_FIELDS_08";
    static constexpr std::string_view kDescription =
        "DUT discards a truncated UDP datagram (wire region < 8 bytes) "
        "(RFC 768 'Fields' MUST)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::udp::UdpStimulusOverrides ov{};
        ov.udp.truncate_to = std::size_t{4};
        ::tc8::sce::udp::emitIngressProbeAndQuery(
            cfg, iface, cfg.dut.mac,
            /*payload=*/nullptr, /*payload_len=*/0,
            ::tc8::sce::udp::kDataPeerPort, ov);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpFields08SM, udp_fields_08)
