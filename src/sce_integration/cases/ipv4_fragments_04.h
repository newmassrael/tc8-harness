#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_fragments_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_fragments_04_sm.h"

namespace tc8::sce::cases {

using Ipv4Fragments04SM = ::SCE::Generated::ipv4_fragments_04::ipv4_fragments_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Fragments04SM>
    : Ipv4FragmentEchoBase<cases::Ipv4Fragments04SM> {
    static constexpr std::string_view kCaseId      = "IPV4_FRAGMENTS_04";
    static constexpr std::string_view kSpecSection = "4.4.4.6";
    static constexpr std::string_view kDescription =
        "DUT must not reassemble fragments whose Protocol fields "
        "differ (RFC 791 §3.2 reassembly-bucket tuple)";

    // Phase 1: frag 0 (proto=ICMP), frag 1 (proto=TCP). Linux's IP
    // layer stores frag 1 in a TCP reassembly bucket (or drops it —
    // either way, it cannot combine with frag 0's ICMP bucket).
    // Phase 2 (scheduled via IStimulusScheduler, fires on
    // `listening_phase2` entry): frag 1 re-sent with proto=ICMP,
    // matching frag 0's bucket → reassemble → Echo Reply. Same
    // state-entry phasing as FRAGMENTS_02.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::ipv4::fragments::FragmentPairParams phase1{};
        phase1.ip_protocol_frag0 = ::tc8::sce::ipv4::fragments::kFragmentsProtocolIcmp;
        // Mismatched protocol on frag 1 — test invariant.
        phase1.ip_protocol_frag1 = ::tc8::sce::ipv4::fragments::kFragmentsProtocolTcp;
        ::tc8::sce::ipv4::fragments::emitFragmentPair(
            iface, cfg, cfg.arp.dut_iface_mac, phase1);

        // Phase 2 — re-send frag 1 with proto=ICMP.
        ::tc8::sce::ipv4::fragments::schedulePhase2FragmentOneOnStateEntry(
            scheduler,
            static_cast<int>(State::Listening_phase2),
            iface, cfg, cfg.arp.dut_iface_mac);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:              return "pass";
            case State::Fail_early_reply:  return "fail:dut_reassembled_mismatched_protocol_fragments";
            case State::Fail_echo_id:      return "fail:echo_id_mismatch_after_protocol_retry";
            case State::Fail_echo_seq:     return "fail:echo_seq_mismatch_after_protocol_retry";
            case State::Fail_data_mismatch: return "fail:reassembled_echo_data_mismatch_protocol_case";
            case State::Fail_timeout:      return "fail:no_echo_reply_after_matched_protocol_retry";
            default:                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Fragments04SM, ipv4_fragments_04)
