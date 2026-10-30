#pragma once

#include <string_view>
#include <vector>

// A case alias: an injected suite's (suite, id) that IS an in-tree case, reported
// under the injected suite's identity. No second implementation — the alias
// registers the target's own CaseEntry (factory, traits, capture filter) under a
// second identity, and records the target in `CaseEntry::alias_of`.
//
// Why the declaration is data resolved at run time, and not a traits header: the
// registrar `gRegisterCase<SM>` is keyed on the state-machine type alone and reads
// TC8_CASE_SUITE at its point of instantiation (case_registry.h). Including an
// in-tree traits header from an injected suite's registration stub would register
// the IN-TREE case under the INJECTED suite's name, one definition silently winning.
// An alias therefore never names a state-machine type; it names the target by its
// (suite, id) string, and the registry copies the target's entry once every
// registrar has run.
//
// ★What an alias asserts, and the premise that makes it true: the alias id asks
// EXACTLY the question the target answers. A consumer id that asks about one
// iteration of a target that runs several asks a different question from the
// whole case's, so it names the iteration: `iteration <n>` points the alias at the
// target's own iteration entry (case_iteration.h), which is a case of its own and
// not a slice of the target's state machine. A target that has not been split into
// iterations has none to name, and the alias is refused at registration.
namespace tc8::sce {

struct CaseAlias {
    std::string_view suite;         // the injected suite that owns the alias id
    std::string_view id;            // the alias's own case id
    std::string_view target_suite;  // the aliased case's suite (the in-tree one)
    std::string_view target_id;     // the aliased case's id
    // The target's executionSurface() digest the consumer last reviewed, from the
    // pointer file's optional `surface <hex>` line; empty when it pins none. A
    // mismatch is REPORTED (--list-cases, the run header), never refused.
    std::string_view pinned_surface = {};
    // The pointer file's optional `iteration <n>` line: the id asks about ONE iteration
    // of the target, not the whole case. 0 = the whole case. The alias then resolves
    // to the target's iteration entry (`<target>_IT<n>`), a case of its own that
    // gates on its own capabilities and runs its own state machine.
    int iteration = 0;
};

// Every alias this build declares, in collection order. Defined by the generated
// gen/cases_stubs/case_aliases.cpp (src/harness/CMakeLists.txt, Pass 4), which
// every tc8-harness build emits — empty when no injection root declares one — so
// the symbol always links. Registered by harness_main before any command runs.
const std::vector<CaseAlias> &declaredCaseAliases();

}  // namespace tc8::sce
