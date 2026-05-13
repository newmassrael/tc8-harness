#pragma once

#include <chrono>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_fragments_common.h"
#include "sce_integration/ipv4_reassembly_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_reassembly_10_sm.h"

namespace tc8::sce::cases {

using Ipv4Reassembly10SM = ::SCE::Generated::ipv4_reassembly_10::ipv4_reassembly_10;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Reassembly10SM>
    : Ipv4FragmentEchoBase<cases::Ipv4Reassembly10SM> {
    static constexpr std::string_view kCaseId      = "IPv4_REASSEMBLY_10";
    static constexpr std::string_view kSpecSection = "4.4.4.7";
    static constexpr std::string_view kDescription =
        "DUT reassembles 2-fragment Echo Request when frag 1 arrives "
        "within ipIniReassembleTimeout, drops bucket when frag 1 "
        "arrives after the timer expires (RFC 791 §3.2)";

    // Two synchronous phases on distinct IP IDs:
    //   Phase A: emitFragmentPair(id=PhaseA, inter_frag_wait=1 s) —
    //     wait < ipfrag_time(2 s), bucket alive, DUT reassembles.
    //   Phase B: emitFragmentPair(id=PhaseB, inter_frag_wait=3 s) —
    //     wait > ipfrag_time, bucket dropped before frag 1', DUT
    //     silent.
    //
    // Both phases run before the SCXML observer arms (kickStimulus
    // returns synchronously, then start() fires). The pcap buffer
    // captures Phase A's Echo Reply during stimulus; the post-start
    // SCXML processes that event first, transitions to phase_b. Phase
    // B emitted no DUT reply during stimulus, so phase_b's 3 s
    // deadline expires → pass. Per-netns ipfrag_time=2 s toggle is
    // installed by smoke-test.sh.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::ipv4::fragments::FragmentPairParams phase_a{};
        phase_a.ip_id_frag0 = ::tc8::sce::ipv4::reassembly::kReassembly10IpIdPhaseA;
        phase_a.ip_id_frag1 = ::tc8::sce::ipv4::reassembly::kReassembly10IpIdPhaseA;
        ::tc8::sce::ipv4::fragments::emitFragmentPair(
            iface, cfg, cfg.arp.dut_iface_mac, phase_a,
            /*initial_wait=*/std::chrono::milliseconds{200},
            /*inter_frag_wait=*/std::chrono::milliseconds{1000},
            /*post_send_wait=*/std::chrono::milliseconds{200});

        ::tc8::sce::ipv4::fragments::FragmentPairParams phase_b{};
        phase_b.ip_id_frag0 = ::tc8::sce::ipv4::reassembly::kReassembly10IpIdPhaseB;
        phase_b.ip_id_frag1 = ::tc8::sce::ipv4::reassembly::kReassembly10IpIdPhaseB;
        ::tc8::sce::ipv4::fragments::emitFragmentPair(
            iface, cfg, cfg.arp.dut_iface_mac, phase_b,
            /*initial_wait=*/std::chrono::milliseconds{0},
            /*inter_frag_wait=*/std::chrono::milliseconds{3000},
            /*post_send_wait=*/std::chrono::milliseconds{200});
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                          return "pass";
            case State::Fail_phase_a_echo_id:          return "fail:echo_id_mismatch_phase_a_within_timer";
            case State::Fail_phase_a_echo_seq:         return "fail:echo_seq_mismatch_phase_a_within_timer";
            case State::Fail_phase_a_data_mismatch:    return "fail:reassembled_echo_data_mismatch_phase_a";
            case State::Fail_phase_a_no_reply:         return "fail:no_echo_reply_phase_a_within_timer";
            case State::Fail_phase_b_replied:          return "fail:dut_replied_phase_b_after_timer_expired";
            default:                                   return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Reassembly10SM, ipv4_reassembly_10)
