#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "sce_integration/declaration_requirement.h"
#include "sce_integration/test_config.h"

namespace tc8::cli {

// The register of everything an operator can declare about the DUT, and the one place a
// case's declaration requirements are evaluated.
//
// Its rows are the TC8_EXPECT_DECLARATION rows of tc8_expect_keys.def: the same file that
// defines the `--expect` keys, so an item cannot be declarable without being registered
// or registered without being declarable. Each item carries its ISO/IEC 9646 class and the
// standard that leaves the choice open:
//
//   PICS   which of two behaviours a standard allows the DUT exhibits; it SELECTS cases
//          (a case testing the other behaviour does not run).
//   PIXIT  a value the DUT chose inside a standard's latitude; a case needing it grades
//          with it, and cannot run without it.
//
// Neither is ever inferred from the DUT's behaviour: a selection read off the behaviour
// under test would grade the DUT against itself.

enum class DeclarationClass { PICS, PIXIT };

struct DeclarationItem {
    std::string_view id;        // "<group>.<name>", the `--expect` key
    DeclarationClass cls;
    std::string_view standard;  // the standard that leaves the choice to the DUT
    // The spellings an enumerated item takes (its DeclarationEnum table); empty for an
    // item whose value is open (a number, a name).
    std::vector<std::string_view> values;
};

// Every item, in tc8_expect_keys.def order.
const std::vector<DeclarationItem> &declarationRegister();

const DeclarationItem *findDeclaration(std::string_view id);

std::string_view declarationClassName(DeclarationClass cls);

// What `cfg` declares for `id`, in the spelling `--expect` takes; nullopt when it is
// undeclared or `id` names no item.
std::optional<std::string> declaredValue(const ::tc8::TestConfig &cfg, std::string_view id);

// Why a requirement can never be met as written: it names no register item, or a value
// its enumerated item does not take. nullopt for a well-formed requirement. A case with
// such a requirement is a harness defect, not a skip.
std::optional<std::string> malformedRequirement(const ::tc8::sce::DeclarationRequirement &req);

// The skip reason for the first requirement `cfg` does not meet, or nullopt when all are
// met: "undeclared_<item>" when the item is not declared, "declared_<item>_<value>" when it
// is declared as a value the case does not run for (dots and other separators become
// underscores, as applicabilitySkipReason spells reasons).
std::optional<std::string> unmetRequirement(const ::tc8::sce::DeclarationRequirement *reqs,
                                            std::size_t count, const ::tc8::TestConfig &cfg);

// The number of keys in the declaration groups (tcp, network) of tc8_expect_keys.def,
// however they are written. Equal to the register's size while every one of them is a
// TC8_EXPECT_DECLARATION row; a test holds the two equal.
std::size_t declarationGroupKeyCount();

}  // namespace tc8::cli
