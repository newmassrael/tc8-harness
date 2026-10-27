#pragma once

#include <string_view>

#include "sce_integration/absence_qualification.h"
#include "sce_integration/dut_requirements.h"
#include "sce_integration/test_config.h"

namespace tc8::cli {

// The liveness anchor (docs/verdict_policy.md Section 2.1, H1): after a window whose
// absence decided the verdict, one exchange the DUT must answer, chosen to share
// as few as possible of the requirements the case grades. The answer shows the DUT
// was live and able to answer at the window's end, which is what turns its silence
// in the window into an observation.
//
// It listens on its OWN capture handle, not on the case's: a case's filter keeps
// out what the case does not grade (a SOME/IP case admits no ARP), and widening
// that filter for the anchor would change what the state machine saw during the
// window. The anchor reports only; nothing it sees reaches the runner.
struct LivenessAnchorRun {
    sce::LivenessAnchorOutcome outcome = sce::LivenessAnchorOutcome::kNotRun;
    sce::LivenessAnchorKind kind = sce::LivenessAnchorKind::kArpExchange;
    // How many of the case's graded requirements the chosen anchor also runs
    // through: 0 is a disjoint anchor; more costs power against a DUT that
    // violates them wholesale, never soundness.
    int shared_requirements = 0;
    int attempts = 0;
    // From the send of the answered attempt to its answer; 0 when unanswered.
    long latency_us = 0;
};

// Runs the anchor on `iface` against the DUT identity in `cfg`. Blocks for at most
// the anchor's bound (a few hundred milliseconds per attempt, two attempts).
LivenessAnchorRun runLivenessAnchor(std::string_view iface, const ::tc8::TestConfig &cfg,
                                    sce::DutRequirements under_test);

}  // namespace tc8::cli
