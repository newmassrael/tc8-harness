#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/cases/udp_fields_01.h"  // kUdpFieldsTesterSrcPort
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_user_interface_07_sm.h"

namespace tc8::sce::cases {

using UdpUserInterface07SM = ::SCE::Generated::udp_user_interface_07::udp_user_interface_07;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpUserInterface07SM>
    : UdpAnyBase<cases::UdpUserInterface07SM> {
    static constexpr std::string_view kCaseId      = "UDP_USER_INTERFACE_07";
    static constexpr std::string_view kSpecSection = "4.6.5.5";
    static constexpr std::string_view kDescription =
        "DUT-emit UDP datagram carries caller-specified Source IP "
        "Address (RFC 768 'User Interface' MUST)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::udp::emitTriggerSendUdp(
            cfg, iface, /*req_id=*/1,
            /*dut_src_port=*/20027,
            /*target_ip_be=*/cfg.ipv4.tester_ip,
            /*target_port=*/::tc8::sce::udp::kDataPort,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            static_cast<std::uint16_t>(::tc8::sce::udp::kUdpDefaultData.size()),
            cases::kUdpFieldsTesterSrcPort,
            cfg.arp.dut_real_mac);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_wrong_src_ip_or_port:  return "fail:dut_emitted_udp_with_wrong_user_interface_src_ip";
            case State::Fail_timeout:               return "fail:no_dut_originated_udp_within_listen_window";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpUserInterface07SM, udp_user_interface_07)
