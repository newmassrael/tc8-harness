#pragma once

#include <cctype>
#include <cstddef>
#include <string>
#include <string_view>

// Single source of truth for case-catalog ("suite") identity. Dependency-free on
// purpose, for the same reason case_id_shape.h is: the case registry
// (case_registry.h, which pulls heavy runner/traits deps) AND the spec inventory
// (spec_inventory.h, which deliberately avoids them) both need it, and a case's
// identity is the pair (suite, id) at EVERY layer — the registry, the inventory
// and every override axis the inventory carries. A layer that resolves by id
// alone lets a same-id case in another catalog inherit what belongs to this one.
namespace tc8::sce {

// SSOT for the in-tree catalog name. The TC8_CASE_SUITE macro defaults to this,
// the CaseEntry.suite field defaults to this, the spec inventory attributes its
// primary file to this, and the CLI's default-suite gate compares against this —
// so the literal "tc8" lives in exactly one place. src/harness/CMakeLists.txt
// derives TC8_DEFAULT_SUITE from this line by path.
inline constexpr std::string_view kDefaultSuite = "tc8";

// A suite name compared the way every layer compares it: ASCII case-insensitive.
// CMake lower-cases a root's suite before stamping TC8_CASE_SUITE, so the
// lower-case form is the canonical one.
inline std::string canonicalSuite(std::string_view suite) {
    std::string out{suite};
    for (auto &c : out) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

inline bool isDefaultSuite(std::string_view suite) {
    return canonicalSuite(suite) == kDefaultSuite;
}

// The textual `suite:ID` form of a case identity — what `--case` accepts, what
// `--list-cases` prints for a non-default suite, and what an inventory-overrides
// key may be written as. The in-tree suite stays bare everywhere, so single-suite
// output and every in-tree overrides key are unchanged by the qualifier existing.
struct QualifiedCaseId {
    std::string_view suite;  // empty when the token carried no qualifier
    std::string_view id;
};

inline QualifiedCaseId splitQualifiedCaseId(std::string_view token) {
    const auto sep = token.find(':');
    if (sep == std::string_view::npos) {
        return {{}, token};
    }
    return {token.substr(0, sep), token.substr(sep + 1)};
}

inline std::string qualifiedCaseId(std::string_view suite, std::string_view id) {
    std::string out;
    if (!isDefaultSuite(suite)) {
        out.assign(suite);
        out.push_back(':');
    }
    out.append(id);
    return out;
}

// The shape CMake enforces on a suite name (tc8_add_case): it becomes a C++
// namespace token and a path segment. Checked again wherever a suite name enters
// from data rather than from the build, so a typo fails there instead of naming a
// catalog nothing registers.
inline bool isWellFormedSuite(std::string_view suite) {
    if (suite.empty()) {
        return false;
    }
    for (std::size_t i = 0; i < suite.size(); ++i) {
        const auto c = static_cast<unsigned char>(suite[i]);
        const bool ok = std::isalpha(c) != 0 || c == '_' || (i > 0 && std::isdigit(c) != 0);
        if (!ok) {
            return false;
        }
    }
    return true;
}

}  // namespace tc8::sce
