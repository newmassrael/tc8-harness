#pragma once

#include <cstddef>
#include <string_view>

// Single source of truth for the TC8 case-id SHAPE — the known variant-tag
// set and the pure functions that parse it. Dependency-free (<string_view>
// only) on purpose: both the case registry (case_registry.h, which pulls
// heavy runner/traits deps) AND the spec inventory (spec_inventory.cpp, which
// deliberately avoids those deps) include this header, so the variant-tag set
// and the category/variant parsing live in exactly ONE place. Putting them
// here is what lets canonicalise() in spec_inventory.cpp reuse stripVariantTag
// instead of re-encoding the "_NEG2..8" digit range — a drift surface.
namespace tc8::sce {

// Case IDs are shaped "<CATEGORY>_<digits>" (e.g. "SOMEIPSRV_FORMAT_01",
// "SOMEIP_ETS_001") OR "<CATEGORY>_<digits>_<TAG>" where TAG is one
// of a small set of known variant tags. The numeric segment drives
// sort order in listSorted(); the category is the prefix before the
// digits (the variant tag, if present, is stripped from both ends
// of the analysis). Enforcing the shape once lets the category be
// derived instead of stored separately, which removes a drift
// surface entirely.
//
// Known variant tags:
//   _NEG             — fault-injection self-validation case paired with
//                      a positive case under the same category. Drives a
//                      negative-path SCXML branch that conformant DUT
//                      emit can never reach
//                      (`reference_dut_fault_injection_pattern.md`).
//   _NEG2 / 3 / 4    — additional fault-injection variants of the SAME
//                      positive case, one per fail-final, for a
//                      multi-guard case whose guards are mutually
//                      exclusive in a single run (e.g. a stale-re-probe
//                      that terminates before the rate-limit silence
//                      window). All map to the same base category +
//                      number; `tools/fault_injection_coverage.json`
//                      is the SSOT for which fail-final each proves.
//
// Adding a new variant tag is a deliberate one-line addition to
// `kKnownVariantTags`; the function shape stays unchanged. The numeric
// suffix keeps the case id a pure identity — the guard each variant
// proves lives in the coverage SSOT, not the file name.
inline constexpr std::string_view kKnownVariantTags[] = {
    "_NEG", "_NEG2", "_NEG3", "_NEG4", "_NEG5", "_NEG6", "_NEG7", "_NEG8"};

constexpr std::string_view stripVariantTag(std::string_view id) {
    for (auto tag : kKnownVariantTags) {
        if (id.size() > tag.size() &&
            id.substr(id.size() - tag.size()) == tag) {
            return id.substr(0, id.size() - tag.size());
        }
    }
    return id;
}

constexpr bool isWellFormedCaseId(std::string_view id) {
    const auto core = stripVariantTag(id);
    const auto pos  = core.rfind('_');
    if (pos == std::string_view::npos || pos + 1 >= core.size()) {
        return false;
    }
    if (pos == 0) {
        return false;  // "_01" has no category
    }
    for (std::size_t i = pos + 1; i < core.size(); ++i) {
        const char c = core[i];
        if (c < '0' || c > '9') {
            return false;
        }
    }
    return true;
}

constexpr std::string_view deriveCategory(std::string_view id) {
    // Precondition: isWellFormedCaseId(id). Caller must have asserted.
    // Variant tag stripped first so the category for "FOO_06" and
    // "FOO_06_NEG" is identically "FOO" — both belong to the same
    // logical group, the variant just changes how they reach a
    // verdict.
    const auto core = stripVariantTag(id);
    return core.substr(0, core.rfind('_'));
}

}  // namespace tc8::sce
