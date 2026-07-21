#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_user_interface_02_sm.h"

namespace tc8::sce::cases {

using UdpUserInterface02SM = ::SCE::Generated::udp_user_interface_02::udp_user_interface_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpUserInterface02SM>
    : UdpAnyBase<cases::UdpUserInterface02SM> {
    static constexpr std::string_view kCaseId      = "UDP_USER_INTERFACE_02";
    static constexpr std::string_view kDescription =
        "Receive operations return the data octets correctly (RFC 768 "
        "'User Interface' MUST)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::udp::emitIngressProbeAndQuery(
            cfg, iface, cfg.dut.mac,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            ::tc8::sce::udp::kUdpDefaultData.size());
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpUserInterface02SM, udp_user_interface_02)
