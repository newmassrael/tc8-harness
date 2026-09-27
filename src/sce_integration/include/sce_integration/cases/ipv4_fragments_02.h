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
    static constexpr std::string_view kDescription =
        "DUT must not reassemble fragments whose Identification "
        "fields differ (RFC 791 §3.2 reassembly-bucket tuple)";
    // Compound case (ipv4_fragments_compound): the property is that mismatched
    // fragments do not join. An expiry report here says a phase-1 bucket died,
    // which is either conforming (the orphan) or a precondition lost before
    // phase 2 — never a verdict on the property. Withheld.
    static constexpr ipv4::fragments::ReassemblyExpiryRole kReassemblyExpiry =
        ipv4::fragments::ReassemblyExpiryRole::kNotGraded;

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
                         ::tc8::sce::StimulusContext& ctx) {
        // frag 0: id1 (matched tuple anchor); frag 1: id2 (mismatched — this
        // is the test invariant). Shared with the _NEG siblings.
        ::tc8::sce::ipv4::fragments::emitFragmentPair(
            ctx.iface, cfg, cfg.arp.dut_iface_mac,
            ::tc8::sce::ipv4::fragments::fragments02Phase1());

        // Phase 2 — re-send frag 1 with id1 so the DUT's bucket A
        // (still holding frag 0 from phase 1) completes. Fires on
        // `listening_phase2` entry, i.e. immediately after SCXML's
        // `listening_phase1` `phase_gap_done` timer transitions.
        ::tc8::sce::ipv4::fragments::schedulePhase2FragmentOneOnStateEntry(
            ctx.scheduler,
            static_cast<int>(State::Listening_phase2),
            ctx.iface, cfg, cfg.arp.dut_iface_mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Fragments02SM, ipv4_fragments_02)
