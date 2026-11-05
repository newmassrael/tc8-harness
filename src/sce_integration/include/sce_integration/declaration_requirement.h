#pragma once

#include <cstddef>
#include <iterator>
#include <string_view>
#include <type_traits>
#include <utility>

namespace tc8::sce {

// What a case needs the operator to have declared about the DUT, stated as data.
//
// ISO/IEC 9646 selects test cases by the implementation's conformance statement: a case
// that tests one of two behaviours a standard allows runs only for an implementation that
// claims it (a PICS item), and a case that grades a value the implementation chose needs
// that value stated (a PIXIT item). The operator states both as declarations
// (`--expect <group>.<name>=<value>`), each a row of the declaration register
// (tc8_expect_keys.def, TC8_EXPECT_DECLARATION; cli/declaration_register.h). A case
// states which it needs:
//
//     static constexpr ::tc8::sce::DeclarationRequirement kDeclarationRequirements[] = {
//         {"tcp.time_wait_rst", "ends_connection"},  // PICS: run only for this behaviour
//         {"tcp.initial_cwnd_segments", {}},         // PIXIT: any declared value
//     };
//
// As data and not code, so the gate evaluates every case's selection in one place, an
// undeclared item and a declared value that excludes the case are distinct skip reasons,
// the register can list for each item the cases it selects, and a requirement naming an
// item the register does not have is caught before it can quietly never match. A
// condition that is not "declared" or "declared as this value" (a value above what a
// case can grade) stays in the case's `applicability` (case_applicability.h).
struct DeclarationRequirement {
    std::string_view item;   // the register id, "<group>.<name>"
    std::string_view value;  // the spelling it must be declared as; empty = any value
};

template <typename Traits, typename = void>
struct has_declaration_requirements : std::false_type {};

template <typename Traits>
struct has_declaration_requirements<Traits, std::void_t<decltype(Traits::kDeclarationRequirements)>>
    : std::true_type {};

// The case's requirements as a pointer and a count; nullptr and 0 when it states none.
template <typename Traits>
constexpr std::pair<const DeclarationRequirement *, std::size_t> declarationRequirementsOf() {
    if constexpr (has_declaration_requirements<Traits>::value) {
        return {std::data(Traits::kDeclarationRequirements), std::size(Traits::kDeclarationRequirements)};
    } else {
        return {nullptr, 0};
    }
}

}  // namespace tc8::sce
