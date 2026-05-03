#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_introduction_02_sm.h"

namespace tc8::sce::cases {

using UdpIntroduction02SM = ::SCE::Generated::udp_introduction_02::udp_introduction_02;

// §4.6.5.6 <allSystemMCastAddr>: 224.0.0.1 (RFC 1112). NBO uint32 =
// 0x010000E0 (little-endian view of 224.0.0.1).
inline constexpr std::uint32_t kAllSystemsMcastBe = 0x010000E0U;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpIntroduction02SM>
    : UdpAnyBase<cases::UdpIntroduction02SM> {
    static constexpr std::string_view kCaseId      = "UDP_INTRODUCTION_02";
    static constexpr std::string_view kSpecSection = "4.6.5.6";
    static constexpr std::string_view kDescription =
        "DUT denies a UDP datagram with all-systems multicast (224.0.0.1) "
        "destination (RFC 1122 §4.1.1, spec inverts the SHOULD-allow per "
        "security negotiation note)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::udp::emitAddressingProbeAndQuery(
            cfg, iface, cases::kAllSystemsMcastBe, cfg.arp.dut_real_mac);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                return "pass";
            case State::Fail_wrong_receipt:  return "fail:dut_received_all_systems_multicast_udp";
            case State::Fail_timeout:        return "fail:no_ut_confirmation_for_multicast_deny";
            default:                         return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpIntroduction02SM, udp_introduction_02)
