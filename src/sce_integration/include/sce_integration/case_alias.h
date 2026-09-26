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
// iteration of a target that runs several is not an alias — the target's phases
// run in sequence and any non-pass final ends the case, so a target `fail` from an
// earlier phase would red an id that asked only about a later one. Such an id is
// mapped by documentation ("covered by tc8:<id>, phase N"), never declared here.
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
};

// Every alias this build declares, in collection order. Defined by the generated
// gen/cases_stubs/case_aliases.cpp (src/harness/CMakeLists.txt, Pass 4), which
// every tc8-harness build emits — empty when no injection root declares one — so
// the symbol always links. Registered by harness_main before any command runs.
const std::vector<CaseAlias> &declaredCaseAliases();

}  // namespace tc8::sce
