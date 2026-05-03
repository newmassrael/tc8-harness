#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_introduction_01_sm.h"

namespace tc8::sce::cases {

using UdpIntroduction01SM = ::SCE::Generated::udp_introduction_01::udp_introduction_01;

// §4.6.5.6 <AIface-0-BcastIP>. The smoke-test netns uses a /24 subnet
// at 172.16.0.0, so the directed broadcast is 172.16.0.255 → NBO
// uint32 0xFF0010AC. Same literal as ADDRESSING_02 — both cases
// observe the same wire shape, just pinning different RFC invariants.
inline constexpr std::uint32_t kIntro01DirectedBroadcastBe = 0xFF0010ACU;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpIntroduction01SM>
    : UdpAnyBase<cases::UdpIntroduction01SM> {
    static constexpr std::string_view kCaseId      = "UDP_INTRODUCTION_01";
    static constexpr std::string_view kSpecSection = "4.6.5.6";
    static constexpr std::string_view kDescription =
        "DUT denies a UDP datagram with directed-broadcast destination "
        "(RFC 1122 §4.1.1, spec inverts the SHOULD-allow per security "
        "negotiation note)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::udp::emitAddressingProbeAndQuery(
            cfg, iface, cases::kIntro01DirectedBroadcastBe, cfg.arp.dut_real_mac);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                return "pass";
            case State::Fail_wrong_receipt:  return "fail:dut_received_directed_broadcast_udp";
            case State::Fail_timeout:        return "fail:no_ut_confirmation_for_directed_broadcast_deny";
            default:                         return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpIntroduction01SM, udp_introduction_01)
