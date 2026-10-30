#include "sce_integration/case_registry.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <utility>

namespace tc8::sce {

namespace {

// Parse "SOMEIPSRV_FORMAT_01" → ("SOMEIPSRV_FORMAT", 1, ""). Tolerates any
// trailing numeric suffix after the final underscore, including zero-padded
// forms like "SOMEIP_ETS_001", and also a known variant tag suffix such as
// "_NEG" (e.g. "IPv4_AUTOCONF_ADDRESS_SELECTION_06_NEG" →
// ("IPV4_AUTOCONF_ADDRESS_SELECTION", 6, "_NEG")). The variant tag is
// stripped before digit parsing so a positive case and its negative variant
// share the same (category, number) primary sort key — listSorted then
// orders the variant after the positive via the final tie-break on full id.
// If the suffix is absent or non-numeric, the full id is returned as the
// category, the number is 0, and the variant tag is empty (still yields a
// stable, deterministic sort).
struct SplitId {
    std::string_view category;
    int              number;
    std::string_view variant_tag;
};

// ASCII case-insensitive equality over the FULL case id (variant tag
// included). Case IDs are the registry's identity key, and every
// inventory-facing path already treats them case-insensitively
// (SpecInventory::canonicalise uppercases before comparing). Resolving
// case-sensitively here while the inventory resolves case-insensitively
// is exactly the split-brain identity P10 closed: a canonical-notation
// CLI arg (`UDP_DatagramLength_01`) failed find() while the same id
// matched the override set. Comparing uppercased keeps the two layers
// in agreement.
//
// Deliberately NOT SpecInventory::canonicalise: that strips `_NEG` /
// `_PLATFORM_KNOWN_FAIL` to derive a primary key, which would fold a
// negative variant onto its positive sibling. The registry keeps those
// distinct, so resolution must preserve the variant tag — only the
// letter case is normalised.
bool equalsIgnoreAsciiCase(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::toupper(static_cast<unsigned char>(a[i])) !=
            std::toupper(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

// Case-insensitive ordering — keeps the listSorted suite axis coherent with the
// case-insensitive identity used by add()/find() (so "TC8" and "tc8" group as
// one suite rather than sorting into separate blocks).
bool lessIgnoreAsciiCase(std::string_view a, std::string_view b) {
    const std::size_t n = std::min(a.size(), b.size());
    for (std::size_t i = 0; i < n; ++i) {
        const int ca = std::toupper(static_cast<unsigned char>(a[i]));
        const int cb = std::toupper(static_cast<unsigned char>(b[i]));
        if (ca != cb) {
            return ca < cb;
        }
    }
    return a.size() < b.size();
}

SplitId splitCaseId(std::string_view id) {
    std::string_view variant_tag;
    std::string_view core = id;
    for (auto tag : kKnownVariantTags) {
        if (core.size() > tag.size() &&
            core.substr(core.size() - tag.size()) == tag) {
            variant_tag = tag;
            core        = core.substr(0, core.size() - tag.size());
            break;
        }
    }
    const auto underscore = core.rfind('_');
    if (underscore == std::string_view::npos || underscore + 1 >= core.size()) {
        return {id, 0, variant_tag};
    }
    int n = 0;
    for (std::size_t i = underscore + 1; i < core.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(core[i]);
        if (!std::isdigit(c)) {
            return {id, 0, variant_tag};
        }
        n = n * 10 + (c - '0');
    }
    return {core.substr(0, underscore), n, variant_tag};
}

}  // namespace

CaseRegistry &CaseRegistry::instance() {
    static CaseRegistry reg;
    return reg;
}

void CaseRegistry::add(CaseEntry entry) {
    for (const auto &existing : entries_) {
        // Identity is (suite, id): the SAME id in a DIFFERENT suite is allowed
        // (that is the whole point of suites — an OEM catalog reusing the
        // literal spec ids). Only a same-(suite, id) pair is a duplicate, which
        // is almost always a copy-paste bug; aborting beats silent first-wins.
        if (equalsIgnoreAsciiCase(existing.suite, entry.suite) &&
            equalsIgnoreAsciiCase(existing.id, entry.id)) {
            std::fprintf(stderr,
                         "tc8-harness: duplicate case registration for "
                         "'%.*s:%.*s' — two TestCaseTraits<> specializations "
                         "share the same (suite, kCaseId) (case-insensitively). "
                         "Aborting before main().\n",
                         static_cast<int>(entry.suite.size()), entry.suite.data(),
                         static_cast<int>(entry.id.size()), entry.id.data());
            std::abort();
        }
    }
    entries_.push_back(std::move(entry));
}

bool CaseRegistry::addAlias(const CaseAlias &alias, std::string *err) {
    const auto fail = [&](const char *why) {
        *err = "case alias " + qualifiedCaseId(alias.suite, alias.id) + " -> " +
               qualifiedCaseId(alias.target_suite, alias.target_id) + ": " + why;
        return false;
    };
    if (!isWellFormedCaseId(alias.id)) {
        return fail("the alias id must end in '_<digits>', as every case id does");
    }
    if (equalsIgnoreAsciiCase(alias.suite, alias.target_suite)) {
        return fail("an alias must live in a different suite than its target; one test "
                    "under two ids in one catalog would be counted twice");
    }
    const CaseEntry *target = find(alias.target_suite, alias.target_id);
    if (target == nullptr) {
        return fail("the target is not a registered case");
    }
    if (target->isAlias()) {
        return fail("the target is itself an alias; name the case it resolves to");
    }
    if (alias.iteration != 0) {
        // The id asks about ONE iteration: the target's own iteration entry, a case
        // of its own. A target with no iterations has none to name.
        if (!target->isComposite()) {
            return fail("the pointer names an iteration, but the target is not made of "
                        "iterations");
        }
        // By the spec's number, which is the number in the iteration's id: a case whose
        // spec skips a number has no iteration at that position.
        const CaseEntry *unit = nullptr;
        for (const std::string_view unit_id : target->iterations) {
            if (iterationOf(unit_id) == alias.iteration) {
                unit = find(alias.target_suite, unit_id);
                break;
            }
        }
        if (unit == nullptr) {
            return fail("the pointer names an iteration the target does not have");
        }
        target = unit;
    }
    if (find(alias.suite, alias.id) != nullptr) {
        return fail("that (suite, id) is already registered");
    }
    // Copied BEFORE the push_back, which may reallocate and invalidate `target`.
    // The string views it carries point at static storage, not into entries_, so
    // they survive the reallocation.
    CaseEntry copy = *target;
    copy.id = alias.id;
    copy.suite = alias.suite;
    copy.category = deriveCategory(alias.id);
    copy.alias_of = {target->suite, target->id};
    copy.alias_surface_pin = alias.pinned_surface;
    entries_.push_back(std::move(copy));
    return true;
}

const CaseEntry *CaseRegistry::find(std::string_view id) const {
    const CaseEntry *match = nullptr;
    for (const auto &e : entries_) {
        if (equalsIgnoreAsciiCase(e.id, id)) {
            if (match != nullptr) {
                // Ambiguous across suites — caller must qualify as suite:id.
                return nullptr;
            }
            match = &e;
        }
    }
    return match;
}

const CaseEntry *CaseRegistry::find(std::string_view suite, std::string_view id) const {
    for (const auto &e : entries_) {
        if (equalsIgnoreAsciiCase(e.suite, suite) && equalsIgnoreAsciiCase(e.id, id)) {
            return &e;
        }
    }
    return nullptr;
}

DutRequirements CaseRegistry::requirementsUnderTest(const CaseEntry &entry) const {
    if (entry.declared_requirements_under_test) {
        return *entry.declared_requirements_under_test;
    }
    // An alias's own id is a consumer's naming; what it runs is its target.
    const QualifiedCaseId self =
        entry.isAlias() ? entry.alias_of : QualifiedCaseId{entry.suite, entry.id};
    const std::string_view positive_id = stripVariantTag(self.id);
    if (positive_id != self.id) {
        const CaseEntry *positive = find(self.suite, positive_id);
        if (positive != nullptr && positive->declared_requirements_under_test) {
            return *positive->declared_requirements_under_test;
        }
    }
    return defaultRequirementsUnderTest(positive_id);
}

bool CaseRegistry::composeIterations(std::string *err) {
    const auto fail = [&](std::string_view id, const std::string &why) {
        *err = "iterated case " + std::string(id) + ": " + why;
        return false;
    };
    // Every iteration entry belongs to a declared case.
    for (const auto &e : entries_) {
        if (!e.isIteration()) {
            continue;
        }
        const std::string_view parent = iterationParent(e.id);
        bool declared = false;
        for (const auto &d : iterated_) {
            declared = declared || (equalsIgnoreAsciiCase(d.suite, e.suite) &&
                                    equalsIgnoreAsciiCase(d.id, parent));
        }
        if (!declared) {
            return fail(parent, "iteration '" + std::string(e.id) +
                                    "' is registered but the case is not declared "
                                    "(TC8_REGISTER_ITERATED_CASE)");
        }
    }
    std::vector<CaseEntry> composed;
    for (const auto &d : iterated_) {
        std::vector<const CaseEntry *> units;
        for (const auto &e : entries_) {
            if (e.isIteration() && equalsIgnoreAsciiCase(e.suite, d.suite) &&
                equalsIgnoreAsciiCase(iterationParent(e.id), d.id)) {
                units.push_back(&e);
            }
        }
        if (units.empty()) {
            return fail(d.id, "declared with no iteration registered");
        }
        std::sort(units.begin(), units.end(), [](const CaseEntry *a, const CaseEntry *b) {
            return iterationOf(a->id) < iterationOf(b->id);
        });
        // The numbers the iterations must carry: the declared spec numbers, or 1..N.
        std::string expected_numbers;
        if (d.numbers.empty()) {
            for (std::size_t i = 0; i < units.size(); ++i) {
                expected_numbers.push_back(static_cast<char>('1' + i));
            }
        } else {
            expected_numbers = std::string(d.numbers);
        }
        std::string found_numbers;
        for (const CaseEntry *u : units) {
            found_numbers.push_back(static_cast<char>('0' + iterationOf(u->id)));
        }
        if (found_numbers != expected_numbers) {
            return fail(d.id, "its iterations are numbered " + found_numbers + ", expected " +
                                  expected_numbers +
                                  (d.numbers.empty()
                                       ? " (1..N without a gap; declare the spec's numbers if "
                                         "it skips one)"
                                       : " as declared"));
        }
        if (find(d.suite, d.id) != nullptr) {
            return fail(d.id, "the id is also registered as a case with a state machine of "
                              "its own; a case is either made of iterations or it is not");
        }
        // One case is one question asked of one setup: the iterations share what the
        // capture and the control channel are set up for.
        const CaseEntry &first = *units[0];
        CaseEntry c = first;
        std::uint32_t caps = 0;
        c.iterations.clear();
        for (const CaseEntry *u : units) {
            if (u->topology != first.topology || u->bpf_group != first.bpf_group ||
                u->bpf_expression != first.bpf_expression ||
                u->control_plane_role != first.control_plane_role) {
                return fail(d.id, "iteration '" + std::string(u->id) +
                                      "' differs from the first in topology, capture filter "
                                      "or control-plane role");
            }
            caps |= u->required_capabilities;
            c.iterations.push_back(u->id);
        }
        c.id = d.id;
        c.suite = d.suite;
        c.category = deriveCategory(d.id);
        c.description = d.description;
        c.required_capabilities = caps;  // the whole case needs what any iteration needs
        c.factory = nullptr;             // no state machine of its own
        composed.push_back(std::move(c));
    }
    for (auto &c : composed) {
        entries_.push_back(std::move(c));
    }
    return true;
}

std::vector<const CaseEntry *> CaseRegistry::listSorted(bool include_deprecated,
                                                        bool include_iterations) const {
    std::vector<const CaseEntry *> out;
    out.reserve(entries_.size());
    for (const auto &e : entries_) {
        if (e.deprecated && !include_deprecated) {
            continue;
        }
        if (e.isIteration() && !include_iterations) {
            continue;
        }
        out.push_back(&e);
    }
    std::sort(out.begin(), out.end(), [](const CaseEntry *a, const CaseEntry *b) {
        // Suite is the primary axis so each catalog groups together. Inter-suite
        // order is deterministic-but-arbitrary (case-insensitive lexicographic);
        // it is NOT guaranteed that "tc8" sorts first — an OEM suite like "vendorx"
        // sorts before it. With no injected suite this is a no-op (single suite).
        if (!equalsIgnoreAsciiCase(a->suite, b->suite)) {
            return lessIgnoreAsciiCase(a->suite, b->suite);
        }
        const auto sa = splitCaseId(a->id);
        const auto sb = splitCaseId(b->id);
        if (sa.category != sb.category) {
            return sa.category < sb.category;
        }
        if (sa.number != sb.number) {
            return sa.number < sb.number;
        }
        return a->id < b->id;
    });
    return out;
}

}  // namespace tc8::sce
