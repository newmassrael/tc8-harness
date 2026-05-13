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
        if (existing.id == entry.id) {
            // Two TestCaseTraits<> specializations claim the same kCaseId.
            // This is almost always a copy-paste bug where a new case header
            // was duplicated without updating the string — the silent
            // first-wins behaviour it would produce is worse than aborting.
            std::fprintf(stderr,
                         "tc8-harness: duplicate case registration for '%.*s'"
                         " — two TestCaseTraits<> specializations share the"
                         " same kCaseId. Aborting before main().\n",
                         static_cast<int>(entry.id.size()), entry.id.data());
            std::abort();
        }
    }
    entries_.push_back(std::move(entry));
}

const CaseEntry *CaseRegistry::find(std::string_view id) const {
    for (const auto &e : entries_) {
        if (e.id == id) {
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
