#pragma once

#include <cstddef>
#include <string>
#include <vector>

// The verdict of a TC8 case made of iterations (case_iteration.h): the conjunction of its
// iterations' verdicts. Pure, so the rule has a tested home apart from the command that
// runs the iterations.
//
// One iteration's outcome is what it reported, as the value after `verdict  : `
// ("pass", "fail:<reason>", "inconclusive:<reason>", "error:<reason>", "skip:<reason>") and
// the exit code it returned. An iteration that printed no verdict line did not conclude,
// which is a fail, as for any run.
//
// The worst iteration decides, the first of equals: a fail outranks everything, then an
// error (the test system broke), then an inconclusive, then a capability skip. A pass is
// the floor, so a case passes only when every iteration did. A fail in one iteration is
// never hidden by what another found, and the verdict names the iteration that decided.

namespace tc8::sce {

struct IterationOutcome {
    std::string verdict;  // the value after `verdict  : `; empty when no line was printed
    int exit_code = 0;
};

struct ConjoinedVerdict {
    std::string verdict;  // the one `verdict  : ` value for the case
    int exit_code = 0;
    int deciding = -1;    // 0-based index of the iteration that decided; -1 when it passed
};

inline std::string verdictClassToken(const std::string &value) {
    const std::size_t colon = value.find(':');
    return colon == std::string::npos ? value : value.substr(0, colon);
}

// How bad a class is for the conjunction. An unreadable class is not a pass.
inline int verdictSeverity(const std::string &cls) {
    if (cls == "fail") return 4;
    if (cls == "error") return 3;
    if (cls == "inconclusive") return 2;
    if (cls == "skip") return 1;
    return cls == "pass" ? 0 : 4;
}

// `error_exit_code` is what a run that did not conclude exits with. `expected` is how many
// iterations the case has: fewer outcomes than that means the run was stopped before they
// all ran, which says nothing about the case unless an iteration already failed.
inline ConjoinedVerdict conjoinIterations(const std::vector<IterationOutcome> &outcomes,
                                          std::size_t expected, int error_exit_code) {
    int worst = -1;
    int worst_severity = -1;
    for (std::size_t i = 0; i < outcomes.size(); ++i) {
        const int sev = outcomes[i].verdict.empty()
                            ? 4
                            : verdictSeverity(verdictClassToken(outcomes[i].verdict));
        if (sev > worst_severity) {
            worst_severity = sev;
            worst = static_cast<int>(i);
        }
    }
    ConjoinedVerdict out;
    if (outcomes.size() < expected && worst_severity < 2) {
        out.verdict = "error:interrupted_before_all_iterations_ran";
        out.exit_code = error_exit_code;
        out.deciding = worst;
        return out;
    }
    if (worst_severity <= 0) {
        out.verdict = "pass";
        out.exit_code = 0;
        return out;
    }
    const IterationOutcome &u = outcomes[static_cast<std::size_t>(worst)];
    const std::string cls = u.verdict.empty() ? "fail" : verdictClassToken(u.verdict);
    const std::size_t colon = u.verdict.find(':');
    const std::string reason = u.verdict.empty()
                                   ? "did_not_return_pass_verdict"
                                   : (colon == std::string::npos ? "" : u.verdict.substr(colon + 1));
    out.verdict = cls + ":iteration_" + std::to_string(worst + 1) + (reason.empty() ? "" : "_" + reason);
    out.exit_code = u.exit_code;
    out.deciding = worst;
    return out;
}

}  // namespace tc8::sce
