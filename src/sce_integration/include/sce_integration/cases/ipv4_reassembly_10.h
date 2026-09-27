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
    static constexpr std::string_view kDescription =
        "DUT reassembles 2-fragment Echo Request when frag 1 arrives "
        "within ipIniReassembleTimeout, drops bucket when frag 1 "
        "arrives after the timer expires (RFC 791 §3.2)";
    // Graded in phase A only: there frag 1 arrives inside the timer, so an
    // expiry report quoting phase A's Identification is a discarded datagram
    // (fail_phase_a_datagram_discarded). In phase B the bucket is MEANT to
    // expire, so listening_phase_b has no transition for the report and the
    // SCXML drops it.
    static constexpr ipv4::fragments::ReassemblyExpiryRole kReassemblyExpiry =
        ipv4::fragments::ReassemblyExpiryRole::kGraded;

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
                         ::tc8::sce::StimulusContext& ctx) {
        // Phase A is shared with the _NEG, which sends it alone.
        ::tc8::sce::ipv4::reassembly::emitReassembly10PhaseA(cfg, ctx.iface);
        ::tc8::sce::ipv4::reassembly::emitReassembly10PhaseB(cfg, ctx.iface);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Reassembly10SM, ipv4_reassembly_10)
