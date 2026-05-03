#pragma once

#include <chrono>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_fragments_common.h"
#include "sce_integration/ipv4_reassembly_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_reassembly_12_sm.h"

namespace tc8::sce::cases {

using Ipv4Reassembly12SM = ::SCE::Generated::ipv4_reassembly_12::ipv4_reassembly_12;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Reassembly12SM>
    : Ipv4FragmentEchoBase<cases::Ipv4Reassembly12SM> {
    static constexpr std::string_view kCaseId      = "IPV4_REASSEMBLY_12";
    static constexpr std::string_view kSpecSection = "4.4.4.7";
    static constexpr std::string_view kDescription =
        "DUT reassembles a 2-fragment Echo Request whose first "
        "fragment carries Low TTL (timer must not shrink) and emits "
        "an Echo Reply with matching id/seq/data (RFC 791 §3.2)";

    // Two-fragment Echo Request with kReassemblyLowTtl (=2) on both
    // halves and a 1 s inter-fragment wait. The smoke-test.sh dut_ns
    // toggle drops `net.ipv4.ipfrag_time` to 2 s so the spec's
    // "wait < ipIniReassembleTimeout - tolerance" condition is
    // exercised against a tight 2 s timer rather than the 30 s kernel
    // default. FragmentPair helper builds the 16 B ICMP body once
    // and slices 8/8 — same shape as FRAGMENTS_01, identical pass
    // criterion (echo_id/seq/data via kFragmentsEchoPayload).
    //
    // Invariant exercised: the 1 s wait sits inside a 2 s timer
    // window. RFC 791 §3.2 mandates the timer remains MAX(TLB,
    // arriving TTL) — Low TTL must not shrink it. A buggy DUT that
    // applied MIN-with-TTL on the 2 s baseline could collapse the
    // window below 1 s and lose the bucket; this case observes that
    // it does not. On Linux the timer ignores TTL entirely (static
    // ipfrag_time per netns), so the bucket survives 2 s regardless
    // of TTL — frag 1 lands at 1 s, reassembly completes, Echo Reply
    // matches. A strict-RFC 791 DUT lands the same wire-level pass
    // since MAX(2, 2) = 2 s. The 30 s/1 s margin in the prior
    // revision was so wide the spec invariant was not actively
    // exercised; tightening to 2 s/1 s narrows the diagnostic gap.
    // See `reference_linux_ip_reassembly_deviations.md`.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::ipv4::fragments::FragmentPairParams params{};
        params.ip_id_frag0 = ::tc8::sce::ipv4::reassembly::kReassembly12IpId;
        params.ip_id_frag1 = ::tc8::sce::ipv4::reassembly::kReassembly12IpId;
        params.ttl_frag0   = ::tc8::sce::ipv4::reassembly::kReassemblyLowTtl;
        params.ttl_frag1   = ::tc8::sce::ipv4::reassembly::kReassemblyLowTtl;

        ::tc8::sce::ipv4::fragments::emitFragmentPair(
            iface, cfg, cfg.arp.dut_iface_mac, params,
            /*initial_wait=*/std::chrono::milliseconds{200},
            /*inter_frag_wait=*/std::chrono::milliseconds{1000},
            /*post_send_wait=*/std::chrono::milliseconds{0});
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                return "pass";
            case State::Fail_echo_id:        return "fail:echo_id_mismatch_after_low_ttl_reassembly";
            case State::Fail_echo_seq:       return "fail:echo_seq_mismatch_after_low_ttl_reassembly";
            case State::Fail_data_mismatch:  return "fail:reassembled_echo_data_mismatch_low_ttl";
            case State::Fail_timeout:        return "fail:no_echo_reply_after_low_ttl_reassembly";
            default:                         return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Reassembly12SM, ipv4_reassembly_12)
