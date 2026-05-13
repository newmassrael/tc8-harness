#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/ipv4_expected.h"
#include "sce_integration/test_case_traits.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_captured.h"
#include "sce_integration/udp_pilot_common.h"

#include "ipv4_fragments_05_sm.h"

namespace tc8::sce::cases {

using Ipv4Fragments05SM = ::SCE::Generated::ipv4_fragments_05::ipv4_fragments_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Fragments05SM> {
    using SM    = cases::Ipv4Fragments05SM;
    using State = SM::PolicyType::State;
    using Event = SM::PolicyType::Event;

    static constexpr std::string_view kCaseId       = "IPv4_FRAGMENTS_05";
    static constexpr std::string_view kSpecSection  = "4.4.4.6";
    static constexpr std::string_view kDescription  =
        "DUT-originated IPv4 UDP datagram is unfragmented (MF=0, "
        "Fragment Offset=0) per RFC 791 §3.2 p25";
    static constexpr bool             kDeprecated   = false;
    static constexpr int              kTopology     = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup     = ::tc8::BpfGroup::Udp;

    using Captured = typename SM::CapturedType;
    using Expected = typename SM::ExpectedType;

    // Spec Test Procedure (v3.0 p121-p140.txt:425):
    //   1. TESTER: Cause DUT to send UDP from DIface-0 with
    //      src_ip=DIface-0-IP, dst_ip=HOST-1-IP, src_port=20001,
    //      dst_port=20000, payload=<UDPDefaultData>.
    //   2. TESTER: Listen <ListenTime> s on DIface-0.
    //   3. DUT: Send UDP message.
    //   4. TESTER: Verify received packet has IP Flags MF=0 +
    //      Fragment Offset=0.
    //
    // Step 1 is emitted as §4.8.5 Upper Tester TriggerSendUdp RPC.
    // The 8 B UDPDefaultData body is well below the 1500 B MTU, so
    // the kernel's egress path emits one IPv4 fragment — MF=0,
    // offset=0 as required. The SCXML asserts those fields (and
    // src_ip + src_port + dst_port to narrow on DUT-origin wire
    // traffic, excluding tester-side UT requests and vsomeip SD
    // multicast).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::udp::emitTriggerSendUdp(
            cfg, iface,
            /*req_id=*/1,
            /*dut_src_port=*/::tc8::sce::udp::kDataPeerPort,  // 20001
            /*target_ip_be=*/cfg.ipv4.tester_ip,
            /*target_port=*/::tc8::sce::udp::kDataPort,        // 20000
            ::tc8::sce::udp::kUdpDefaultData.data(),
            static_cast<std::uint16_t>(::tc8::sce::udp::kUdpDefaultData.size()),
            /*tester_src_port=*/20100,
            /*dut_mac=*/cfg.arp.dut_real_mac);
    }

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        ::tc8::sce::udp::dispatchUdpFrame<SM>(c, sm, ev);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:              return "pass";
            case State::Fail_fragmented:   return "fail:dut_emitted_udp_with_nonzero_fragment_fields";
            case State::Fail_timeout:      return "fail:no_dut_originated_udp_within_listen_window";
            default:                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Fragments05SM, ipv4_fragments_05)
