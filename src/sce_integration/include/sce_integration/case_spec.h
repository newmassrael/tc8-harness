#pragma once

#include <string>
#include <vector>

#include "case_registry.h"
#include "spec_inventory.h"

namespace tc8::sce {

// Which catalog entry answers which inventory axis for one registered case.
//
// For an authored case both views are the same entry: its own (suite, id). They
// differ only for an alias (case_alias.h), and the split is by what each axis
// DESCRIBES, decided per axis rather than per entry — one overrides entry can
// carry axes that need both answers:
//
//   execution — timing_serial, requires_secondary_iface, expect_overrides, the
//     negative row(s), the vsomeip DUT flavor. They decide what stimulus runs,
//     against which DUT deployment, on which lane, and what the case's own
//     self-check falsifies. An alias asserts it IS the target, so these are the
//     TARGET's, or the alias would run a quietly different test under the
//     target's name. The negative row is included deliberately: the flip belongs
//     to the case, not to whoever names it, and a consumer that needs a
//     different flip is authoring a variant, not an alias. Its mis-resolution is
//     also loud (a flipped run that passes is a Fail), which makes it the safest
//     of these to inherit.
//
//   own — section, expected, platform_known_fail. Claims about a catalog's
//     coverage story and about one platform's deviation, not about the test. An
//     alias inheriting the target's platform_known_fail would let the consumer's
//     row be excused by a deviation measured on another deployment.
//
// Either pointer is nullptr when that catalog does not hold the case.
struct CaseSpec {
    const SpecCase *own = nullptr;
    const SpecCase *execution = nullptr;
};

CaseSpec resolveCaseSpec(const SpecInventory &inventory, const CaseEntry &entry);

// A 16-hex-digit digest of what a case EXECUTES as: the traits fields CaseEntry
// copies from TestCaseTraits (topology, capture filter, capabilities, control
// plane role, DUT-ready barrier requirement, deprecation) plus the execution axes `spec.execution` resolves.
// `spec` may be empty (no inventory), and then only the traits contribute.
//
// It exists for aliases. An alias asserts "this IS the in-tree case", and the
// in-tree case keeps changing; a consumer that pins the digest in its pointer file
// learns, when it bumps the harness, which of its aliases now run something
// different — reported, never refused, so the harness's own maintenance cannot
// block a consumer's build.
//
// ⚠ What it deliberately leaves out, and why that is not a gap:
//   - the SCXML text. It is rewritten by work that changes no behaviour (prose
//     re-expression, comment edits), and a digest that fires on every such commit
//     is switched off within a week. A behavioural change to a target reaches the
//     in-tree lane as a VERDICT change first, since CI re-runs it on every push.
//   - the description, the section and every `_ref`: prose, not execution.
//   - platform_known_fail and expected: they are the alias's own axes, not the
//     target's (see the split above), so they cannot drift underneath it.
std::string executionSurface(const CaseEntry &entry, const CaseSpec &spec);

// One message per alias whose OWN catalog entry declares an execution axis.
// Such a declaration would be ignored — execution axes resolve against the
// target — so it is refused rather than dropped: either the axis belongs on the
// target, or the consumer's case differs from the target and is a variant to
// author, not an alias. Empty when every alias is consistent.
std::vector<std::string> aliasAxisConflicts(const SpecInventory &inventory,
                                            const CaseRegistry &registry);

}  // namespace tc8::sce
