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

#include "ipv4_addressing_02_sm.h"

namespace tc8::sce::cases {

using Ipv4Addressing02SM = ::SCE::Generated::ipv4_addressing_02::ipv4_addressing_02;

// Spec §4.4.4.5 <directedBroadcastAddress>. Subnet-scoped: the host
// octet(s) under the netmask are set to all-ones. For the smoke-test
// /24 at 172.16.0.0 this is 172.16.0.255 → NBO uint32 0xFF0010AC.
// Keep this case-local rather than reading from TestConfig — spec
// says "Directed Broadcast" is a property of the packet the tester
// sends, not a DUT-side expectation. A future multi-topology pilot
// would parameterize this via a new `ipv4.directed_broadcast` expect
// key, but today the netns is fixed /24.
inline constexpr std::uint32_t kDirectedBroadcastBe = 0xFF0010ACU;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Addressing02SM> {
    using SM    = cases::Ipv4Addressing02SM;
    using State = SM::PolicyType::State;
    using Event = SM::PolicyType::Event;

    static constexpr std::string_view kCaseId       = "IPv4_ADDRESSING_02";
    static constexpr std::string_view kSpecSection  = "4.4.4.5";
    static constexpr std::string_view kDescription  =
        "DUT silently discards an IPv4 UDP packet whose Destination "
        "Address is the Directed Broadcast address (RFC 791 §3.2, "
        "RFC 1122 §3.2.1.3)";
    static constexpr bool             kDeprecated   = false;
    static constexpr int              kTopology     = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup     = ::tc8::BpfGroup::Udp;

    using Captured = typename SM::CapturedType;
    using Expected = typename SM::ExpectedType;

    // Shared stimulus body with IPv4_ADDRESSING_01 via
    // `emitAddressingProbeAndQuery`. The SCXML's
    // `{$expected_received}=0` parameter flips this case's polarity;
    // the probe's `dst_ip = <directedBroadcastAddress>` is the only
    // wire-level difference from ADDRESSING_01.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::udp::emitAddressingProbeAndQuery(
            cfg, iface, cases::kDirectedBroadcastBe, cfg.dut.mac);
    }

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        ::tc8::sce::udp::dispatchUdpFrame<SM>(c, sm, ev);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                return "pass";
            case State::Fail_wrong_receipt:  return "fail:dut_received_directed_broadcast";
            case State::Fail_timeout:        return "fail:no_ut_confirmation_for_directed_broadcast";
            default:                         return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Addressing02SM, ipv4_addressing_02)
