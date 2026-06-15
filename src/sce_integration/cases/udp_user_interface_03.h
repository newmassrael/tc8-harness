#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_user_interface_03_sm.h"

namespace tc8::sce::cases {

using UdpUserInterface03SM = ::SCE::Generated::udp_user_interface_03::udp_user_interface_03;

inline constexpr std::uint16_t kUserInterface03SrcPort = 20019;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpUserInterface03SM>
    : UdpAnyBase<cases::UdpUserInterface03SM> {
    static constexpr std::string_view kCaseId      = "UDP_USER_INTERFACE_03";
    static constexpr std::string_view kSpecSection = "4.6.5.5";
    static constexpr std::string_view kDescription =
        "Receive operations return the source UDP port correctly (RFC "
        "768 'User Interface' MUST)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::udp::emitIngressProbeAndQuery(
            cfg, iface, cfg.dut.mac,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            ::tc8::sce::udp::kUdpDefaultData.size(),
            cases::kUserInterface03SrcPort);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpUserInterface03SM, udp_user_interface_03)
