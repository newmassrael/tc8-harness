#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_fragments_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_fragments_03_sm.h"

namespace tc8::sce::cases {

using Ipv4Fragments03SM = ::SCE::Generated::ipv4_fragments_03::ipv4_fragments_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Fragments03SM>
    : Ipv4FragmentEchoBase<cases::Ipv4Fragments03SM> {
    static constexpr std::string_view kCaseId      = "IPv4_FRAGMENTS_03";
    static constexpr std::string_view kSpecSection = "4.4.4.6";
    static constexpr std::string_view kDescription =
        "DUT must not reassemble fragments whose Source Address "
        "fields differ (RFC 791 §3.2 reassembly-bucket tuple)";

    // Phase 1: frag 0 (src=tester_ip), frag 1 (src=host2_ip). The
    // DUT stores each in its own bucket; no reassembly.
    // Phase 2 (scheduled via IStimulusScheduler, fires on
    // `listening_phase2` entry): frag 1 re-sent with src=tester_ip,
    // matching frag 0's bucket → reassemble → Echo Reply. Same
    // state-entry phasing as FRAGMENTS_02.
    //
    // kFragmentsHost2IpBe (172.16.0.99) sits in the same /24 as
    // tester and DUT so the DUT's rp_filter path accepts the
    // fragment into a reassembly bucket; the test invariant is
    // tuple-mismatch rejection, not rp_filter.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::ipv4::fragments::FragmentPairParams phase1{};
        // frag 0: tester src (default — std::nullopt resolves to
        // cfg.icmpv4.tester_ip inside emitFragmentPair).
        // frag 1: host2 src (mismatched — this is the test invariant).
        phase1.src_ip_frag1 = ::tc8::sce::ipv4::fragments::kFragmentsHost2IpBe;
        ::tc8::sce::ipv4::fragments::emitFragmentPair(
            iface, cfg, cfg.arp.dut_iface_mac, phase1);

        // Phase 2 — re-send frag 1 with tester src (matching frag 0's
        // bucket). The helper defaults to tester_ip on the retry.
        ::tc8::sce::ipv4::fragments::schedulePhase2FragmentOneOnStateEntry(
            scheduler,
            static_cast<int>(State::Listening_phase2),
            iface, cfg, cfg.arp.dut_iface_mac);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:              return "pass";
            case State::Fail_early_reply:  return "fail:dut_reassembled_mismatched_src_fragments";
            case State::Fail_echo_id:      return "fail:echo_id_mismatch_after_src_retry";
            case State::Fail_echo_seq:     return "fail:echo_seq_mismatch_after_src_retry";
            case State::Fail_data_mismatch: return "fail:reassembled_echo_data_mismatch_src_case";
            case State::Fail_timeout:      return "fail:no_echo_reply_after_matched_src_retry";
            default:                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Fragments03SM, ipv4_fragments_03)
