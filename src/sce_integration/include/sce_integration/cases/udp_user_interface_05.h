#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_user_interface_05_sm.h"

namespace tc8::sce::cases {

using UdpUserInterface05SM = ::SCE::Generated::udp_user_interface_05::udp_user_interface_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpUserInterface05SM>
    : UdpAnyBase<cases::UdpUserInterface05SM> {
    static constexpr std::string_view kCaseId      = "UDP_USER_INTERFACE_05";
    static constexpr std::string_view kDescription =
        "DUT-emit UDP datagram carries caller-specified Source Port "
        "(RFC 768 'User Interface' MUST). Mirror of FIELDS_01 distinct "
        "by spec section + per-case src_port.";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::udp::emitTriggerSendUdp(
            cfg, iface, /*req_id=*/1,
            /*dut_src_port=*/20025,
            /*target_ip_be=*/cfg.ipv4.tester_ip,
            /*target_port=*/::tc8::sce::udp::kDataPort,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            static_cast<std::uint16_t>(::tc8::sce::udp::kUdpDefaultData.size()),
            ::tc8::ut::kTesterSrcPort,
            cfg.dut.mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpUserInterface05SM, udp_user_interface_05)
