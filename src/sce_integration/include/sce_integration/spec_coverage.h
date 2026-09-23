#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "case_registry.h"
#include "spec_inventory.h"

namespace tc8::sce {

// The `--list-cases --vs-spec` gap report as data: ONE suite's registered cases
// measured against THAT suite's catalog. Kept apart from its rendering so the
// scoping — the thing that decides whether the CI spec-coverage gate means
// anything once a second suite is registered — is unit-testable.
struct SpecCoverage {
    struct Category {
        std::string name;
        std::vector<const SpecCase *> registered;             // incl. registered-and-deferred
        std::vector<const SpecCase *> missing;                // expected, not registered
        std::vector<const SpecCase *> deferred;               // registered and expected:false
        std::vector<const SpecCase *> unregistered_deferred;  // neither
    };
    std::vector<Category> categories;  // sorted by name
    // Registered in the suite, absent from its catalog. The registered id as is,
    // so a harness variant tag with no spec parent is recognisable.
    std::vector<std::string> registered_only;
};

// Registered cases OF `suite` against the inventory cases OF `suite`. A case
// registered under any other suite counts for nothing here, whatever its id: an
// injected catalog reusing a spec id is a different test, and counting it would
// let the gate pass on a spec case the scoped catalog does not register.
// nullopt when the inventory holds no catalog for `suite` — there is nothing to
// measure against, and an empty report would read as full coverage.
std::optional<SpecCoverage> computeSpecCoverage(const CaseRegistry &registry,
                                                const SpecInventory &inventory,
                                                std::string_view suite);

}  // namespace tc8::sce
