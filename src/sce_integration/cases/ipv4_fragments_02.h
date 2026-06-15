#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_fragments_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_fragments_02_sm.h"

namespace tc8::sce::cases {

using Ipv4Fragments02SM = ::SCE::Generated::ipv4_fragments_02::ipv4_fragments_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Fragments02SM>
    : Ipv4FragmentEchoBase<cases::Ipv4Fragments02SM> {
    static constexpr std::string_view kCaseId      = "IPv4_FRAGMENTS_02";
    static constexpr std::string_view kSpecSection = "4.4.4.6";
    static constexpr std::string_view kDescription =
        "DUT must not reassemble fragments whose Identification "
        "fields differ (RFC 791 §3.2 reassembly-bucket tuple)";

    // Phase 1 (synchronous within kickStimulus): frag 0 carries id1,
    // frag 1 carries id2 — different tuples. DUT stores each in its
    // own reassembly bucket; neither completes so no Echo Reply.
    // Phase 2 (scheduled via IStimulusScheduler, fires from tick()
    // on `listening_phase2` entry): frag 1 retried with id1,
    // completing bucket A → DUT reassembles → Echo Reply.
    //
    // State-entry-driven scheduling decouples phase 2's emit moment
    // from `listening_phase1`'s `<send delay="2s"/>` value: the
    // runner observes the SCXML transition into `listening_phase2`
    // and fires the queued action on the same `tick()`. Frag 0's
    // DUT-side bucket survives at Linux default ipfrag_time=30 s, so
    // the inter-state latency is irrelevant.
    //
    // L2 destination is DUT-unicast: Linux IP reassembly accepts
    // any pkt_type, but unicast keeps the envelope symmetric with
    // the §4.3 error cases and rules out L2-dispatch skew.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::ipv4::fragments::FragmentPairParams phase1{};
        // frag 0: id1 (matched tuple anchor).
        phase1.ip_id_frag0 = ::tc8::sce::ipv4::fragments::kFragmentsIpId1;
        // frag 1: id2 (mismatched — this is the test invariant).
        phase1.ip_id_frag1 = ::tc8::sce::ipv4::fragments::kFragmentsIpId2;
        ::tc8::sce::ipv4::fragments::emitFragmentPair(
            iface, cfg, cfg.arp.dut_iface_mac, phase1);

        // Phase 2 — re-send frag 1 with id1 so the DUT's bucket A
        // (still holding frag 0 from phase 1) completes. Fires on
        // `listening_phase2` entry, i.e. immediately after SCXML's
        // `listening_phase1` `phase_gap_done` timer transitions.
        ::tc8::sce::ipv4::fragments::schedulePhase2FragmentOneOnStateEntry(
            scheduler,
            static_cast<int>(State::Listening_phase2),
            iface, cfg, cfg.arp.dut_iface_mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Fragments02SM, ipv4_fragments_02)
