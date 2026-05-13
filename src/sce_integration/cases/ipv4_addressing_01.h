#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/test_case_traits.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_captured.h"
#include "sce_integration/udp_pilot_common.h"

#include "ipv4_addressing_01_sm.h"

namespace tc8::sce::cases {

using Ipv4Addressing01SM = ::SCE::Generated::ipv4_addressing_01::ipv4_addressing_01;

// Spec §4.4.4.5 <limitedBroadcastAddress>. RFC 919 §2 fixes the
// literal to 255.255.255.255. NBO-stored uint32 = 0xFFFFFFFF (every
// byte 0xFF regardless of host endianness).
inline constexpr std::uint32_t kLimitedBroadcastBe = 0xFFFFFFFFU;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Addressing01SM> {
    using SM    = cases::Ipv4Addressing01SM;
    using State = SM::PolicyType::State;
    using Event = SM::PolicyType::Event;

    static constexpr std::string_view kCaseId       = "IPv4_ADDRESSING_01";
    static constexpr std::string_view kSpecSection  = "4.4.4.5";
    static constexpr std::string_view kDescription  =
        "DUT accepts an IPv4 UDP packet whose Destination Address is "
        "the Limited Broadcast address (RFC 791 §3.2, RFC 1122 §3.2.1.3)";
    static constexpr bool             kDeprecated   = false;
    static constexpr int              kTopology     = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup     = ::tc8::BpfGroup::Udp;

    using Captured = typename SM::CapturedType;
    using Expected = typename SM::ExpectedType;

    // Spec Test Procedure (v3.0 p001-p020.txt:478):
    //   1. TESTER sends a UDP Message to <limitedBroadcastAddress>.
    //   2. TESTER verifies via Upper Tester that the DUT received it.
    //
    // Shared stimulus body with IPv4_ADDRESSING_02 in udp_pilot_common's
    // `emitAddressingProbeAndQuery` — both cases are structurally
    // identical except for the broadcast literal and the SCXML's
    // `{$expected_received}` polarity.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::udp::emitAddressingProbeAndQuery(
            cfg, iface, cases::kLimitedBroadcastBe, cfg.arp.dut_real_mac);
    }

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        ::tc8::sce::udp::dispatchUdpFrame<SM>(c, sm, ev);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                return "pass";
            case State::Fail_wrong_receipt:  return "fail:dut_did_not_receive_limited_broadcast";
            case State::Fail_timeout:        return "fail:no_ut_confirmation_for_limited_broadcast";
            default:                         return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Addressing01SM, ipv4_addressing_01)
