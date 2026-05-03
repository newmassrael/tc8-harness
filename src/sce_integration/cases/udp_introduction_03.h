#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/icmpv4_captured.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_case_traits.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_introduction_03_sm.h"

namespace tc8::sce::cases {

using UdpIntroduction03SM = ::SCE::Generated::udp_introduction_03::udp_introduction_03;

// Port disjoint from kDataPort (20000) and ut::kPort (30600) so
// tc8-dut has no listener bound — Linux's UDP layer responds with
// ICMP type=3 code=3 per RFC 1122 §4.1.3.1 SHOULD.
inline constexpr std::uint16_t kIntro03UnusedDstPort = 20999;

inline constexpr std::array<std::uint8_t, 1> kIntro03Probe{0xA5};

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpIntroduction03SM> {
    using SM    = cases::UdpIntroduction03SM;
    using State = SM::PolicyType::State;
    using Event = SM::PolicyType::Event;

    static constexpr std::string_view kCaseId       = "UDP_INTRODUCTION_03";
    static constexpr std::string_view kSpecSection  = "4.6.5.6";
    static constexpr std::string_view kDescription  =
        "DUT emits ICMP Destination Unreachable / Port Unreachable when "
        "a UDP datagram arrives on a port without a pending LISTEN call "
        "(RFC 1122 §4.1.3.1 SHOULD)";
    static constexpr bool             kDeprecated   = false;
    static constexpr int              kTopology     = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup     = ::tc8::BpfGroup::Icmpv4;

    using Captured = typename SM::CapturedType;
    using Expected = typename SM::ExpectedType;

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        // Linux's ICMP error-emit path requires PACKET_HOST L2 dst — see
        // `reference_icmp_packet_host_gate.md`. Default Eth-broadcast
        // sets PACKET_BROADCAST and the kernel suppresses the error.
        ::tc8::sce::udp::UdpStimulusOverrides ov{};
        ov.eth_dst_override = cfg.arp.dut_real_mac;
        ::tc8::sce::udp::emitUdpStimulus(
            cfg, iface,
            cfg.ipv4.dut_iface_ip,
            ::tc8::sce::udp::kDataPeerPort,
            cases::kIntro03UnusedDstPort,
            cases::kIntro03Probe.data(),
            cases::kIntro03Probe.size(),
            ::tc8::sce::udp::kUdpPilotInitialWait,
            ov);
    }

    // BPF=icmp captures only the DUT's ICMP reply; UDP stimulus is emit-
    // only (no observation needed). Reuse the ICMPv4 dispatch helper so
    // the captured `type` / `code` / `src_ip` slots populate uniformly.
    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        ::tc8::sce::icmpv4::dispatchAnyIcmpFrame<SM>(c, sm, ev);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:              return "pass";
            case State::Fail_wrong_icmp:   return "fail:dut_emitted_non_port_unreachable_icmp";
            case State::Fail_timeout:      return "fail:no_dut_icmp_port_unreachable_within_listen_window";
            default:                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpIntroduction03SM, udp_introduction_03)
