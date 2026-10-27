#pragma once

#include "tc8/upper_tester_fault_catalog.h"

#include "sce_integration/arp_captured.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/test_case_traits.h"
#include "sce_integration/test_config.h"

namespace tc8::sce {

// The stimulus of the §4.2.4.2 Request-reception `_NEG` cases (arp_required_reply_neg):
// arm kArpFaultIgnoreWellFormedRequest, then inject exactly the positive's Request by
// running the positive's own stimulus, so the frame the fault swallows is the frame
// the positive grades and the two cannot drift apart. Both machines carry the same
// ArpCaptured context, which is what lets one stimulus serve both.
//
// A free function with its own name rather than an inherited `stimulus`: the
// capability audit charges a helper's demands to every caller by name, and a base
// member named `stimulus` would charge kCapIngressFault to every case.
//
// Kept out of _arp_traits_base.h for the reason that header gives: the fault catalogue
// it needs must not reach the 64 cases that do not.
template <typename PositiveSM>
inline void emitPositiveRequestUnderIgnoreFault(::tc8::ArpCaptured &c, const ::tc8::TestConfig &cfg,
                                               ::tc8::sce::StimulusContext &ctx) {
    emitIngressFlavorArm(cfg, ctx.iface, ::tc8::ut::kArpFaultIgnoreWellFormedRequest);
    TestCaseTraits<PositiveSM>::stimulus(c, cfg, ctx);
}

}  // namespace tc8::sce
