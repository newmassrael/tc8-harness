#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string_view>
#include <vector>

#include "tc8/bpf_group.h"

#include "case_id_shape.h"
#include "test_case_traits.h"
#include "test_config.h"
#include "test_runner.h"

namespace tc8::sce {

// SSOT for the in-tree catalog name. The TC8_CASE_SUITE macro defaults to this,
// the CaseEntry.suite field defaults to this, and the CLI's default-suite gate
// compares against this — so the literal "tc8" lives in exactly one place.
inline constexpr std::string_view kDefaultSuite = "tc8";

}  // namespace tc8::sce

// A case's catalog ("suite"). The in-tree catalog is kDefaultSuite ("tc8"); an
// injected OEM catalog defines this macro (via its CMake-generated register stub)
// to its own name so it can reuse the same literal spec case-ids as the in-tree
// catalog without colliding. A case's identity is the pair (suite, id) at every
// layer.
//
// ODR INVARIANT: an OEM stub that overrides TC8_CASE_SUITE MUST also generate its
// state machines under a matching --cpp-namespace-prefix, yielding DISTINCT SM
// types. gRegisterCase<SM> is an inline variable template — registering the SAME
// SM type from two TUs that saw different TC8_CASE_SUITE values is an ODR
// violation (one definition silently wins). Distinct suite => distinct
// cpp-namespace-prefix => distinct SM type => safe. Never reuse an SM type across
// suites.
#ifndef TC8_CASE_SUITE
#define TC8_CASE_SUITE (::tc8::sce::kDefaultSuite)
#endif

namespace tc8::sce {

// Flat metadata copy of TestCaseTraits<SM>, carried by value so the CLI and
// reporting layers never need to know the underlying state-machine type.
// The factory accepts the parsed `TestConfig` so per-Context configuration
// (e.g. SomeIpExpectations) is pushed at construction — there is no
// post-construction `configure()` hop on `ITestRunner` for it.
struct CaseEntry {
    std::string_view id;
    std::string_view category;
    // NB: there is deliberately no `spec_section` field. A case's spec
    // section is DERIVED from the spec inventory (docs/spec/case_inventory.json,
    // mined from the TC8 spec PDF — the SSOT) by canonical id at the point
    // of display, exactly as `category` is derived from the id below. A
    // hand-authored per-case copy would drift from the spec.
    std::string_view description;
    bool deprecated = false;
    int topology = 1;
    ::tc8::BpfGroup bpf_group = ::tc8::BpfGroup::SomeIp;
    // Optional per-case capture-filter override (from TestCaseTraits<>::
    // kBpfExpression). Empty = derive from bpf_group. Points at a static
    // string literal so the view outlives the registry. See
    // `capture::bpf::resolveCaptureFilter`.
    std::string_view bpf_expression = {};
    // Optional DUT-control capability requirement (from TestCaseTraits<>::
    // kRequiredCapabilities; bitmask of DutCapability). 0 = no requirement.
    // The CLI capability-skip gate skips a case whose bits are not all present
    // in the selected --dut-control backend's capabilities() (Tier 2 2b#4).
    std::uint32_t required_capabilities = 0;
    std::function<std::unique_ptr<ITestRunner>(const ::tc8::TestConfig &)> factory;
    // Catalog this case belongs to. Defaults to kDefaultSuite so every existing
    // construction (which omits it) stays in the in-tree suite; the OEM-suite
    // register stub sets it via TC8_CASE_SUITE. Identity is (suite, id).
    std::string_view suite = kDefaultSuite;
};

// Meyers-singleton registry populated at static-init time by each case
// header's TC8_REGISTER_CASE() expansion. Order of registration is
// non-deterministic across translation units — listSorted() applies a
// stable (category, numeric suffix) sort for CLI output.
class CaseRegistry {
public:
    static CaseRegistry &instance();

    void add(CaseEntry entry);

    // Unqualified lookup: resolves an id that is unique across all suites.
    // Returns nullptr if no match OR if the id is ambiguous (present in more
    // than one suite) — callers then qualify via find(suite, id).
    const CaseEntry *find(std::string_view id) const;

    // Qualified lookup by (suite, id) — both compared case-insensitively.
    const CaseEntry *find(std::string_view suite, std::string_view id) const;

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

// The case-id SHAPE primitives — kKnownVariantTags, stripVariantTag,
// isWellFormedCaseId, deriveCategory — live in case_id_shape.h so the spec
// inventory (spec_inventory.cpp) can share the SAME variant-tag set without
// pulling this header's runner/traits deps. See that header for the rationale.

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
            CaseEntry{T::kCaseId, deriveCategory(T::kCaseId), T::kDescription, T::kDeprecated,
                      T::kTopology, T::kBpfGroup, bpfExpressionOf<T>(), requiredCapabilitiesOf<T>(),
                      [](const ::tc8::TestConfig &cfg) {
                          return std::unique_ptr<ITestRunner>(new TestRunner<StateMachine>(cfg));
                      },
                      TC8_CASE_SUITE});
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
