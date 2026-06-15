#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_padding_02_sm.h"

namespace tc8::sce::cases {

using UdpPadding02SM = ::SCE::Generated::udp_padding_02::udp_padding_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpPadding02SM>
    : UdpAnyBase<cases::UdpPadding02SM> {
    static constexpr std::string_view kCaseId      = "UDP_Padding_02";
    static constexpr std::string_view kSpecSection = "4.6.5.3";
    static constexpr std::string_view kDescription =
        "DUT-emit UDP datagram with even payload size carries no "
        "trailing padding bytes (RFC 768 'Fields')";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::udp::emitTriggerSendUdp(
            cfg, iface, /*req_id=*/1,
            /*dut_src_port=*/20030,
            /*target_ip_be=*/cfg.ipv4.tester_ip,
            /*target_port=*/::tc8::sce::udp::kDataPort,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            static_cast<std::uint16_t>(::tc8::sce::udp::kUdpDefaultData.size()),
            ::tc8::ut::kTesterSrcPort,
            cfg.dut.mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpPadding02SM, udp_padding_02)
