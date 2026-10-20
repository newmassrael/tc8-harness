#pragma once

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include "stimulus/tx_observer.h"  // kNoSpecStep

// The specification's own procedure for a case, carried so a watcher can say which step
// a send, a frame or a transition is.
//
// WHY THIS EXISTS
// ---------------
// The state machine's states (`listening_phase1`, ...) are the harness's view of a case.
// The specification describes the same case as a numbered procedure ("1. the tester
// sends the request, 2. the DUT answers, 3. the tester verifies"), and an operator reads
// a live run against THAT. Only the case knows how the two line up, so the case says so.
//
// WHAT THE HARNESS DOES WITH IT
// -----------------------------
// It carries it and nothing else. The text is never parsed, shortened or acted on: it
// goes into the live stream (`spec` line) escaped and verbatim, and a number goes onto
// the `tx` and `transition` lines it applies to. No verdict reads any of it. The text
// itself therefore belongs to the case's author (an OEM module keeps it in its own case
// header); this header holds the shape, not a word of any specification.
//
// HOW A CASE DECLARES IT (all optional; a case without `kSpec` behaves exactly as before)
// --------------------------------------------------------------------------------------
//
//     template <> struct TestCaseTraits<MySM> : ... {
//         static constexpr SpecStep kSteps[] = {
//             {1, "TESTER", "..."}, {2, "DUT", "..."}, {3, "TESTER", "..."}};
//         static constexpr SpecCheck kChecks[] = {{3, "a)", "..."}};
//         // Which step a transition decides. An empty from/to/event matches anything.
//         static constexpr SpecTransition kTransitions[] = {
//             {"", "listening_phase2", "", 2},   // keyed by the state it arrives at
//             {"", "pass", "", 3}};
//         static constexpr SpecProcedure kSpec{kSteps, kChecks, kTransitions};
//     };
//
// and tags the sends of a step with `::tc8::stimulus::TxSpecStep step(1);` around them
// (stimulus/tx_observer.h). Two sends cannot be wrapped that way and are named apart: the
// SYN and ACK of a handshake made inside an emitter (`TxConnectSteps`), and the SYN+ACK
// of an accept made on the capture thread (`TcpAcceptService`'s `accept_step`).
//
// MATCHING A TRANSITION
// ---------------------
// A transition line takes the steps of the rows that match it. No match leaves it
// untagged. Several matching rows that name different steps are all kept: one transition
// can be the evidence for more than one step (a message checked for its content by one
// step and for its timing by a later one), and the case says so by writing a row for
// each. The harness lists them, ascending and each once, and never picks between them;
// rows that agree on a step count once, so a catch-all row and a specific one that name
// the same step are not a second step. A row is a filter on what the harness records for
// a transition (the state it left, the state it arrived at, the event that caused it),
// so a case whose transitions share a trigger tells them apart by their states.
namespace tc8::sce {

// A read-only view of a case's constexpr array.
template <typename T>
struct SpecList {
    const T    *data = nullptr;
    std::size_t size = 0;

    constexpr SpecList() = default;
    template <std::size_t N>
    constexpr SpecList(const T (&items)[N]) : data(items), size(N) {}

    constexpr const T *begin() const { return data; }
    constexpr const T *end() const { return data + size; }
};

// One numbered step of the specified procedure. `n` is the case's own numbering and
// must not be negative (kNoSpecStep is the "none" value).
struct SpecStep {
    int              n;
    std::string_view actor;  // who performs it, in the case's own words
    std::string_view text;
};

// One item to verify at a step, with the mark the specification gives it ("a)").
struct SpecCheck {
    int              step;
    std::string_view mark;
    std::string_view text;
};

// Which step a transition decides. Empty fields match anything.
struct SpecTransition {
    std::string_view from;
    std::string_view to;
    std::string_view event;
    int              step;
};

struct SpecProcedure {
    SpecList<SpecStep>       steps;
    SpecList<SpecCheck>      checks;
    SpecList<SpecTransition> transitions;
};

// The steps a transition decides, ascending and without repeats; empty when no row
// matches (see "MATCHING A TRANSITION").
inline std::vector<int> specStepsForTransition(const SpecProcedure &spec,
                                               std::string_view from, std::string_view to,
                                               std::string_view event) {
    std::vector<int> steps;
    for (const SpecTransition &row : spec.transitions) {
        if ((!row.from.empty() && row.from != from) || (!row.to.empty() && row.to != to) ||
            (!row.event.empty() && row.event != event)) {
            continue;
        }
        const auto at = std::lower_bound(steps.begin(), steps.end(), row.step);
        if (at == steps.end() || *at != row.step) {
            steps.insert(at, row.step);
        }
    }
    return steps;
}

// What is wrong with a case's table against the machine it is attached to, one sentence
// each; empty when it is sound. A table that names a state the machine does not have
// drifted from the machine (a state renamed, a case regenerated), and a drifted table
// would otherwise just stop tagging, silently. Reported to the stream, never a verdict.
inline std::vector<std::string> validateSpec(const SpecProcedure &spec,
                                             const std::vector<std::string> &state_ids) {
    std::vector<std::string> problems;
    const auto isState = [&](std::string_view id) {
        for (const auto &s : state_ids) {
            if (s == id) return true;
        }
        return false;
    };
    const auto isStep = [&](int n) {
        for (const SpecStep &s : spec.steps) {
            if (s.n == n) return true;
        }
        return false;
    };

    for (std::size_t i = 0; i < spec.steps.size; ++i) {
        const int n = spec.steps.data[i].n;
        if (n < 0) {
            problems.push_back("steps[" + std::to_string(i) + "]: n " + std::to_string(n) +
                               " is negative");
        }
        for (std::size_t j = 0; j < i; ++j) {
            if (spec.steps.data[j].n == n) {
                problems.push_back("steps[" + std::to_string(i) + "]: n " + std::to_string(n) +
                                   " is declared twice");
                break;
            }
        }
    }
    for (std::size_t i = 0; i < spec.checks.size; ++i) {
        if (!isStep(spec.checks.data[i].step)) {
            problems.push_back("checks[" + std::to_string(i) + "]: step " +
                               std::to_string(spec.checks.data[i].step) +
                               " is not a declared step");
        }
    }
    for (std::size_t i = 0; i < spec.transitions.size; ++i) {
        const SpecTransition &row = spec.transitions.data[i];
        const std::string at = "transitions[" + std::to_string(i) + "]: ";
        if (!isStep(row.step)) {
            problems.push_back(at + "step " + std::to_string(row.step) +
                               " is not a declared step");
        }
        if (!row.from.empty() && !isState(row.from)) {
            problems.push_back(at + "from '" + std::string(row.from) +
                               "' is not a state of the machine");
        }
        if (!row.to.empty() && !isState(row.to)) {
            problems.push_back(at + "to '" + std::string(row.to) +
                               "' is not a state of the machine");
        }
        if (row.from.empty() && row.to.empty() && row.event.empty()) {
            problems.push_back(at + "matches every transition");
        }
    }
    return problems;
}

}  // namespace tc8::sce
