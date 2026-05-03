#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_user_interface_04_sm.h"

namespace tc8::sce::cases {

using UdpUserInterface04SM = ::SCE::Generated::udp_user_interface_04::udp_user_interface_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpUserInterface04SM>
    : UdpAnyBase<cases::UdpUserInterface04SM> {
    static constexpr std::string_view kCaseId      = "UDP_USER_INTERFACE_04";
    static constexpr std::string_view kSpecSection = "4.6.5.5";
    static constexpr std::string_view kDescription =
        "Receive operations return the source IP address correctly (RFC "
        "768 'User Interface' MUST)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        // Conformant src_ip = tester_ip; SCXML asserts the UT
        // Confirmation surfaces the same value back. No overrides
        // beyond the default cfg-driven src_ip.
        ::tc8::sce::udp::emitIngressProbeAndQuery(
            cfg, iface, cfg.arp.dut_real_mac,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            ::tc8::sce::udp::kUdpDefaultData.size());
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                  return "pass";
            case State::Fail_field_mismatch:   return "fail:dut_received_udp_with_wrong_src_ip_in_confirmation";
            case State::Fail_timeout:          return "fail:no_ut_confirmation_for_src_ip_check";
            default:                           return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpUserInterface04SM, udp_user_interface_04)
