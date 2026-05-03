#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/cases/udp_introduction_02.h"  // kAllSystemsMcastBe
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_invalid_addresses_01_sm.h"

namespace tc8::sce::cases {

using UdpInvalidAddresses01SM = ::SCE::Generated::udp_invalid_addresses_01::udp_invalid_addresses_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpInvalidAddresses01SM>
    : UdpAnyBase<cases::UdpInvalidAddresses01SM> {
    static constexpr std::string_view kCaseId      = "UDP_INVALID_ADDRESSES_01";
    static constexpr std::string_view kSpecSection = "4.6.5.7";
    static constexpr std::string_view kDescription =
        "DUT discards a UDP datagram whose Source IP Address is "
        "all-systems multicast (RFC 1122 §4.1.3.6 + §3.2.1.3 MUST)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::udp::UdpStimulusOverrides ov{};
        ov.src_ip_override = cases::kAllSystemsMcastBe;
        ::tc8::sce::udp::emitIngressProbeAndQuery(
            cfg, iface, cfg.arp.dut_real_mac,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            ::tc8::sce::udp::kUdpDefaultData.size(),
            ::tc8::sce::udp::kDataPeerPort, ov);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                return "pass";
            case State::Fail_wrong_receipt:  return "fail:dut_received_udp_with_multicast_src_ip";
            case State::Fail_timeout:        return "fail:no_ut_confirmation_for_multicast_src_discard";
            default:                         return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpInvalidAddresses01SM, udp_invalid_addresses_01)
