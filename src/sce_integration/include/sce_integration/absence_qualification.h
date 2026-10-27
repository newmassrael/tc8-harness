#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

#include "ixit_config.h"
#include "verdict.h"

namespace tc8::sce {

// Whether a run's verdict rests on an absence, and what to make of it when the
// test hypotheses behind that absence were not established
// (docs/verdict_policy.md Section 2.1). Pure: the CLI gathers the run facts and
// acts on the answer, so the rule has a tested home apart from the command that
// runs it.

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

// The window bound a final declares (H3), resolved against the run's IXIT values.
struct AbsenceBound {
    bool declared = false;
    bool valid = false;
    std::int64_t us = 0;
};

// "ParamListenTime" reads the run's IXIT value; "<n>ms" and "<n>s" are literals
// for a requirement that states its own time. Anything else is declared but not
// valid, which no window can satisfy.
inline AbsenceBound resolveAbsenceBound(std::string_view bound, const ::tc8::IxitConfig &ixit) {
    AbsenceBound b;
    if (bound.empty()) {
        return b;
    }
    b.declared = true;
    if (bound == "ParamListenTime") {
        b.valid = true;
        b.us = static_cast<std::int64_t>(ixit.param_listen_time_ms) * 1000;
        return b;
    }
    std::int64_t scale = 0;
    std::string_view digits = bound;
    if (digits.size() > 2 && digits.substr(digits.size() - 2) == "ms") {
        scale = 1000;
        digits.remove_suffix(2);
    } else if (digits.size() > 1 && digits.back() == 's') {
        scale = 1000 * 1000;
        digits.remove_suffix(1);
    } else {
        return b;
    }
    std::int64_t value = 0;
    for (const char c : digits) {
        if (c < '0' || c > '9' || value > (std::int64_t{1} << 40)) {
            return b;
        }
        value = value * 10 + (c - '0');
    }
    b.valid = true;
    b.us = value * scale;
    return b;
}

// How far a measured window may read short of the timer that closed it and still
// count as covering its bound: the run loop's idle quantum (test_command.cpp
// kIdleWait). The window is measured from the transition that entered the
// source state, which is stamped after that state's onentry armed the timer, so
// even an exact window reads a little short; a literal bound equal to its window
// (a spec "within 500 ms") must not fail H3 on that alone. The static audit still
// requires every window timer's delay to be at least its bound, so this slack never
// admits a window that was authored short.
inline constexpr std::int64_t kWindowMeasurementSlackUs = 20 * 1000;

// The facts the CLI gathered. `capture_reason` names the H2 hole when
// `capture_whole` is false (the capture accounting decides which one).
struct AbsenceFacts {
    bool frame_decided = false;
    bool capture_whole = false;
    std::string_view capture_reason = {};
    // The window the deciding transition closed (ITestRunner::finalWindowUs).
    std::optional<std::int64_t> window_us = std::nullopt;
    AbsenceBound bound = {};
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

// The first of H2 and H3 that does not hold for an absence-claiming verdict, as
// its reason; empty when both hold. H2 first: without a whole capture the window's
// length says nothing. An `observed_quiescence` fail must declare its bound — a
// silence graded against no stated allowance cannot tell slowness from omission;
// a pass is held to a bound only when its final declares one.
inline std::string_view unestablishedBeforeAnchor(const Verdict &v, const AbsenceFacts &facts) {
    if (!facts.capture_whole) {
        return facts.capture_reason.empty() ? std::string_view{"capture_completeness_unknown_absence_unproven"}
                                            : facts.capture_reason;
    }
    if (!facts.bound.declared) {
        return v.role == "observed_quiescence" ? std::string_view{"absence_bound_undeclared_absence_unproven"}
                                               : std::string_view{};
    }
    if (!facts.bound.valid) {
        return "absence_bound_unparseable_absence_unproven";
    }
    if (!facts.window_us || *facts.window_us + kWindowMeasurementSlackUs < facts.bound.us) {
        return "window_shorter_than_bound_absence_unproven";
    }
    return {};
}

// Whether the CLI must run the anchor at all: only for a verdict that claims an
// absence and whose H2 and H3 already hold — otherwise the verdict is downgraded
// on that ground, and the exchange would only add traffic.
inline bool needsLivenessAnchor(const Verdict &v, const AbsenceFacts &facts) {
    return claimsAbsence(v, facts.frame_decided) && unestablishedBeforeAnchor(v, facts).empty();
}

// The verdict after the absence hypotheses: unchanged unless it claims an absence
// and H2, H3 or H1 does not hold, in which case it becomes `inconclusive` with the
// role `property_unobserved` and a reason naming the first missing hypothesis.
inline Verdict qualifyAbsence(Verdict v, const AbsenceFacts &facts) {
    if (!claimsAbsence(v, facts.frame_decided)) {
        return v;
    }
    auto downgrade = [](std::string_view reason) {
        return Verdict{VerdictClass::Inconclusive, std::string(reason), "property_unobserved", {}};
    };
    const std::string_view before = unestablishedBeforeAnchor(v, facts);
    if (!before.empty()) {
        return downgrade(before);
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
