#pragma once

#include <functional>
#include <memory>
#include <string_view>
#include <vector>

#include "tc8/bpf_group.h"

#include "test_case_traits.h"
#include "test_config.h"
#include "test_runner.h"

namespace tc8::sce {

// Flat metadata copy of TestCaseTraits<SM>, carried by value so the CLI and
// reporting layers never need to know the underlying state-machine type.
// The factory accepts the parsed `TestConfig` so per-Context configuration
// (e.g. SomeIpExpectations) is pushed at construction — there is no
// post-construction `configure()` hop on `ITestRunner` for it.
struct CaseEntry {
    std::string_view id;
    std::string_view category;
    std::string_view spec_section;
    std::string_view description;
    bool deprecated = false;
    int topology = 1;
    ::tc8::BpfGroup bpf_group = ::tc8::BpfGroup::SomeIp;
    std::function<std::unique_ptr<ITestRunner>(const ::tc8::TestConfig &)> factory;
};

// Meyers-singleton registry populated at static-init time by each case
// header's TC8_REGISTER_CASE() expansion. Order of registration is
// non-deterministic across translation units — listSorted() applies a
// stable (category, numeric suffix) sort for CLI output.
class CaseRegistry {
public:
    static CaseRegistry &instance();

    void add(CaseEntry entry);

    const CaseEntry *find(std::string_view id) const;

    // Returns non-owning pointers into the internal vector. Pointers stay
    // valid for the lifetime of the program (registry is never mutated
    // after static init completes).
    std::vector<const CaseEntry *> listSorted(bool include_deprecated = false) const;

    std::size_t size() const {
        return entries_.size();
    }

    // Publicly default-constructible so unit tests can exercise add/find/
    // listSorted against a private instance without touching the global
    // singleton created by `instance()`.
    CaseRegistry() = default;

private:
    std::vector<CaseEntry> entries_;
};

// Case IDs are shaped "<CATEGORY>_<digits>" (e.g. "SOMEIPSRV_FORMAT_01",
// "SOMEIP_ETS_001") OR "<CATEGORY>_<digits>_<TAG>" where TAG is one
// of a small set of known variant tags. The numeric segment drives
// sort order in listSorted(); the category is the prefix before the
// digits (the variant tag, if present, is stripped from both ends
// of the analysis). Enforcing the shape once lets the category be
// derived instead of stored separately, which removes a drift
// surface entirely.
//
// Known variant tags:
//   _NEG — fault-injection self-validation case paired with a
//          positive case under the same category. Drives the
//          negative-path SCXML branches that conformant DUT emit
//          can never reach (`reference_dut_fault_injection_pattern.md`).
//
// Adding a new variant tag is a deliberate one-line addition to
// `kKnownVariantTags`; the function shape stays unchanged.
inline constexpr std::string_view kKnownVariantTags[] = {"_NEG"};

constexpr std::string_view stripVariantTag(std::string_view id) {
    for (auto tag : kKnownVariantTags) {
        if (id.size() > tag.size() &&
            id.substr(id.size() - tag.size()) == tag) {
            return id.substr(0, id.size() - tag.size());
        }
    }
    return id;
}

constexpr bool isWellFormedCaseId(std::string_view id) {
    const auto core = stripVariantTag(id);
    const auto pos  = core.rfind('_');
    if (pos == std::string_view::npos || pos + 1 >= core.size()) {
        return false;
    }
    if (pos == 0) {
        return false;  // "_01" has no category
    }
    for (std::size_t i = pos + 1; i < core.size(); ++i) {
        const char c = core[i];
        if (c < '0' || c > '9') {
            return false;
        }
    }
    return true;
}

constexpr std::string_view deriveCategory(std::string_view id) {
    // Precondition: isWellFormedCaseId(id). Caller must have asserted.
    // Variant tag stripped first so the category for "FOO_06" and
    // "FOO_06_NEG" is identically "FOO" — both belong to the same
    // logical group, the variant just changes how they reach a
    // verdict.
    const auto core = stripVariantTag(id);
    return core.substr(0, core.rfind('_'));
}

// Variable-template registrar: instantiating `gRegisterCase<SM>` runs the
// constructor which copies TestCaseTraits<SM> fields into a CaseEntry and
// pushes it onto the global registry. Because the variable is `inline`,
// duplicate inclusions across translation units collapse to a single
// instance at link time — the constructor fires exactly once per SM.
template <typename StateMachine> struct CaseRegistrar {
    CaseRegistrar() {
        using T = TestCaseTraits<StateMachine>;
        static_assert(isWellFormedCaseId(T::kCaseId), "TestCaseTraits<SM>::kCaseId must end in '_<digits>', "
                                                      "e.g. 'SOMEIPSRV_FORMAT_01' or 'SOMEIP_ETS_025'");
        CaseRegistry::instance().add(
            CaseEntry{T::kCaseId, deriveCategory(T::kCaseId), T::kSpecSection, T::kDescription, T::kDeprecated,
                      T::kTopology, T::kBpfGroup, [](const ::tc8::TestConfig &cfg) {
                          return std::unique_ptr<ITestRunner>(new TestRunner<StateMachine>(cfg));
                      }});
    }
};

template <typename StateMachine> inline const CaseRegistrar<StateMachine> gRegisterCase{};

}  // namespace tc8::sce

// Declares a static-init registration for the given state-machine type.
// Must appear at namespace scope in the case's header (cases/<id>.h).
// The anonymous-namespace reference ODR-uses the variable-template
// specialization, forcing its constructor to run in any translation unit
// that pulls the header into the link. `Tag` just has to be a unique
// identifier token within the including TU.
#define TC8_REGISTER_CASE(StateMachineType, Tag)                                                                       \
    namespace {                                                                                                        \
    [[maybe_unused]] const auto &_tc8_reg_##Tag = ::tc8::sce::gRegisterCase<StateMachineType>;                         \
    }
