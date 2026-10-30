#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#include "test_config.h"

namespace tc8::sce {

class IDutControl;

// Whether a case applies to the DUT in the configuration it is in.
//
// A case may declare, beside its capability requirement, that it was written for one
// configuration of the DUT (one binary run as an active or a passive node, with or
// without a feature) and has nothing to grade in another:
//
//     static std::optional<std::string> applicability(const ::tc8::TestConfig &,
//                                                    ::tc8::sce::IDutControl &);
//
// An empty result means the case applies and runs. A string is the reason it does not,
// and the run ends as a skip, a verdict of its own, instead of a stimulus that was
// never performed.
//
// WHY THIS IS NOT THE CAPABILITY GATE. A capability is a property of the TEST SYSTEM:
// which seams the selected --dut-control backend provides. Applicability is a property
// of the DUT's CONFIGURATION: a seam may be present and the case still not apply. The
// two skips have different causes and different remedies (provide the seam / run the
// DUT in another configuration), so they carry different verdict reasons
// (`skip:requires_capability_...` against `skip:not_applicable_...`) and are decided by
// different declarations.
//
// A SKIP NEVER STANDS IN FOR A FAILED QUERY. Only an affirmative "this does not apply"
// may be returned. A function that could not learn the configuration (the DUT did not
// answer, the variable is unset) returns empty: the case then runs and, if it needed
// that configuration, ends inconclusive, which is the honest class for a run that could
// not tell. Skipping on a failed query would turn a broken test system into a green
// report.
//
// It is called once per run, in the CLI gate before the stimulus, on the thread that
// runs the case; it may use the DUT-control handle it is given, with the same care the
// capability query takes (a request to the DUT is traffic the capture can see).
using ApplicabilityFn = std::optional<std::string> (*)(const ::tc8::TestConfig &, IDutControl &);

template <typename Traits, typename = void>
struct has_applicability : std::false_type {};

template <typename Traits>
struct has_applicability<
    Traits, std::void_t<decltype(Traits::applicability(std::declval<const ::tc8::TestConfig &>(),
                                                       std::declval<IDutControl &>()))>>
    : std::true_type {};

template <typename Traits>
inline constexpr bool has_applicability_v = has_applicability<Traits>::value;

// The case's function, or nullptr when it declares none (it always applies).
template <typename Traits>
constexpr ApplicabilityFn applicabilityOf() {
    if constexpr (has_applicability_v<Traits>) {
        return &Traits::applicability;
    } else {
        return nullptr;
    }
}

// The verdict line's reason as one token: lower-case letters, digits and '_'. A reason
// is built from configuration values, and the orchestrator reads the line by splitting
// it, so a space or a ':' in it would cut the reason short or read as a second field.
inline std::string applicabilitySkipReason(std::string_view reason) {
    std::string out;
    out.reserve(reason.size());
    for (const char c : reason) {
        const bool keep = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
        if (keep) {
            out.push_back(c);
        } else if (c >= 'A' && c <= 'Z') {
            out.push_back(static_cast<char>(c - 'A' + 'a'));
        } else {
            out.push_back('_');
        }
    }
    if (out.empty()) {
        out = "unspecified";
    }
    return out;
}

// `skip:not_applicable_<reason>`, the text after "verdict  : ".
inline std::string applicabilitySkipVerdict(std::string_view reason) {
    return "skip:not_applicable_" + applicabilitySkipReason(reason);
}

}  // namespace tc8::sce
