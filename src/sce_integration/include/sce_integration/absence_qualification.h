#pragma once

#include <string_view>

#include "verdict.h"

namespace tc8::sce {

// Whether a run's verdict rests on an absence, and what to make of it when the
// test hypotheses behind that absence were not established
// (docs/verdict_policy.md Section 2.1). Pure: the CLI gathers the run facts and acts on
// the answer, so the rule has a tested home apart from the command that runs it.

// What the liveness anchor (H1) came to.
enum class LivenessAnchorOutcome {
    kNotRun,           // not needed, or not reached because an earlier hypothesis failed
    kAnswered,         // the DUT answered after the window
    kUnanswered,       // sent, and nothing answered within the anchor's bound
    kNoDutAddress,     // the run has no DUT address to address an anchor to
    kUnavailable,      // the harness could not send or listen (offline replay, no tap)
};

// The verdict claims an absence: a `pass` the final transition of which no frame
// drove — conservatively, so a pass evaluated from a state query is held to the
// same hypotheses, which can cost a conclusion but never forge one — or a `fail`
// whose role says its evidence is a silence. A frame-decided verdict carries its
// evidence in the trace and claims no absence; a timer-reached `observed_violation`
// grades a value that was observed and claims none either.
inline bool claimsAbsence(const Verdict &v, bool frame_decided) {
    if (frame_decided) {
        return false;
    }
    if (v.cls == VerdictClass::Pass) {
        return true;
    }
    return v.cls == VerdictClass::Fail &&
           (v.role == "observed_quiescence" || v.role == "fault_injection_inert");
}

// The facts the CLI gathered. `capture_reason` names the H2 hole when
// `capture_whole` is false (the capture accounting decides which one).
struct AbsenceFacts {
    bool frame_decided = false;
    bool capture_whole = false;
    std::string_view capture_reason = {};
    LivenessAnchorOutcome anchor = LivenessAnchorOutcome::kNotRun;
};

// The H1 reason for an anchor that did not establish liveness; empty when it did
// (or was not run).
constexpr std::string_view livenessAnchorReason(LivenessAnchorOutcome outcome) {
    switch (outcome) {
        case LivenessAnchorOutcome::kUnanswered: return "liveness_anchor_unanswered_absence_unproven";
        case LivenessAnchorOutcome::kNoDutAddress: return "liveness_anchor_no_dut_address_absence_unproven";
        case LivenessAnchorOutcome::kUnavailable: return "liveness_anchor_unavailable_absence_unproven";
        case LivenessAnchorOutcome::kNotRun:
        case LivenessAnchorOutcome::kAnswered: return {};
    }
    return {};
}

// Whether the CLI must run the anchor at all: only for a verdict that claims an
// absence and whose capture already holds — when H2 fails the verdict is
// downgraded on that ground, and the exchange would only add traffic.
inline bool needsLivenessAnchor(const Verdict &v, bool frame_decided, bool capture_whole) {
    return capture_whole && claimsAbsence(v, frame_decided);
}

// The verdict after the absence hypotheses: unchanged unless it claims an absence
// and H2 or H1 does not hold, in which case it becomes `inconclusive` with the
// role `property_unobserved` and a reason naming the first missing hypothesis.
// H2 is checked first: without a whole capture, an answered anchor would not make
// the absence an observation.
inline Verdict qualifyAbsence(Verdict v, const AbsenceFacts &facts) {
    if (!claimsAbsence(v, facts.frame_decided)) {
        return v;
    }
    auto downgrade = [](std::string_view reason) {
        return Verdict{VerdictClass::Inconclusive, std::string(reason), "property_unobserved"};
    };
    if (!facts.capture_whole) {
        return downgrade(facts.capture_reason.empty() ? std::string_view{"capture_completeness_unknown_absence_unproven"}
                                                      : facts.capture_reason);
    }
    if (facts.anchor != LivenessAnchorOutcome::kAnswered) {
        // kNotRun here means the caller skipped an anchor this verdict needed; that
        // is not evidence of liveness, so it reads as unavailable.
        const std::string_view reason = livenessAnchorReason(facts.anchor);
        return downgrade(reason.empty() ? livenessAnchorReason(LivenessAnchorOutcome::kUnavailable) : reason);
    }
    return v;
}

}  // namespace tc8::sce
