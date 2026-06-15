#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_user_interface_01_sm.h"

namespace tc8::sce::cases {

using UdpUserInterface01SM = ::SCE::Generated::udp_user_interface_01::udp_user_interface_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpUserInterface01SM>
    : UdpAnyBase<cases::UdpUserInterface01SM> {
    static constexpr std::string_view kCaseId      = "UDP_USER_INTERFACE_01";
    static constexpr std::string_view kSpecSection = "4.6.5.5";
    static constexpr std::string_view kDescription =
        "User interface allows creation of N new receive ports "
        "(RFC 768 'User Interface' MUST). Spec asserts DUT can create "
        "10 receive ports on demand via OpCreateUdpReceivePorts.";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::udp::emitCreateUdpReceivePorts(
            cfg, iface,
            /*req_id=*/1,
            /*count=*/10,
            ::tc8::ut::kTesterSrcPort,
            cfg.dut.mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpUserInterface01SM, udp_user_interface_01)
