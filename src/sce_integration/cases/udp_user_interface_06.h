#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_user_interface_06_sm.h"

namespace tc8::sce::cases {

using UdpUserInterface06SM = ::SCE::Generated::udp_user_interface_06::udp_user_interface_06;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpUserInterface06SM>
    : UdpAnyBase<cases::UdpUserInterface06SM> {
    static constexpr std::string_view kCaseId      = "UDP_USER_INTERFACE_06";
    static constexpr std::string_view kSpecSection = "4.6.5.5";
    static constexpr std::string_view kDescription =
        "DUT-emit UDP datagram carries caller-specified Destination "
        "Port (RFC 768 'User Interface' MUST)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::udp::emitTriggerSendUdp(
            cfg, iface, /*req_id=*/1,
            /*dut_src_port=*/20029,  // disjoint from FIELDS_02 (20002)
            /*target_ip_be=*/cfg.ipv4.tester_ip,
            /*target_port=*/20026,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            static_cast<std::uint16_t>(::tc8::sce::udp::kUdpDefaultData.size()),
            ::tc8::ut::kTesterSrcPort,
            cfg.arp.dut_real_mac);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                  return "pass";
            case State::Fail_wrong_dst_port:   return "fail:dut_emitted_udp_with_wrong_user_interface_dst_port";
            case State::Fail_timeout:          return "fail:no_dut_originated_udp_within_listen_window";
            default:                           return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpUserInterface06SM, udp_user_interface_06)
