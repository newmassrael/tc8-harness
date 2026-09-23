#include "sce_integration/spec_coverage.h"

#include <algorithm>
#include <set>
#include <unordered_map>

namespace tc8::sce {

std::optional<SpecCoverage> computeSpecCoverage(const CaseRegistry &registry,
                                                const SpecInventory &inventory,
                                                std::string_view suite) {
    if (!inventory.hasSuite(suite)) {
        return std::nullopt;
    }
    const std::string scope = canonicalSuite(suite);

    // Canonical ids registered IN THE SCOPE (strip _NEG / _PLATFORM_KNOWN_FAIL
    // so harness variant tags don't masquerade as distinct spec entries).
    std::vector<const CaseEntry *> scoped;
    std::set<std::string> registered_canon;
    for (const auto *e : registry.listSorted(/*include_deprecated=*/true)) {
        if (canonicalSuite(e->suite) != scope) {
            continue;
        }
        scoped.push_back(e);
        registered_canon.insert(SpecInventory::canonicalise(std::string{e->id}));
    }

    SpecCoverage out;
    std::unordered_map<std::string, std::size_t> by_category;
    std::set<std::string> spec_canon;
    for (const auto &sc : inventory.cases()) {
        if (sc.suite != scope) {
            continue;
        }
        const std::string canon = SpecInventory::canonicalise(sc.id);
        spec_canon.insert(canon);
        auto it = by_category.find(sc.category);
        if (it == by_category.end()) {
            it = by_category.emplace(sc.category, out.categories.size()).first;
            out.categories.push_back(SpecCoverage::Category{sc.category, {}, {}, {}, {}});
        }
        auto &row = out.categories[it->second];
        const bool is_registered = registered_canon.count(canon) > 0;
        const bool is_deferred = !sc.expected;
        if (is_registered) {
            row.registered.push_back(&sc);
            if (is_deferred) {
                row.deferred.push_back(&sc);
            }
        } else if (is_deferred) {
            row.unregistered_deferred.push_back(&sc);
        } else {
            row.missing.push_back(&sc);
        }
    }
    std::sort(out.categories.begin(), out.categories.end(),
              [](const SpecCoverage::Category &a, const SpecCoverage::Category &b) {
                  return a.name < b.name;
              });

    for (const auto *e : scoped) {
        if (spec_canon.count(SpecInventory::canonicalise(std::string{e->id})) == 0) {
            out.registered_only.emplace_back(e->id);
        }
    }
    return out;
}

}  // namespace tc8::sce
