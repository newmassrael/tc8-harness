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
