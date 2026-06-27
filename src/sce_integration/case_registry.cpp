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

std::vector<const CaseEntry *> CaseRegistry::listSorted(bool include_deprecated) const {
    std::vector<const CaseEntry *> out;
    out.reserve(entries_.size());
    for (const auto &e : entries_) {
        if (e.deprecated && !include_deprecated) {
            continue;
        }
        out.push_back(&e);
    }
    std::sort(out.begin(), out.end(), [](const CaseEntry *a, const CaseEntry *b) {
        // Suite is the primary axis so each catalog groups together. Inter-suite
        // order is deterministic-but-arbitrary (case-insensitive lexicographic);
        // it is NOT guaranteed that "tc8" sorts first — an OEM suite like "hkmc"
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
