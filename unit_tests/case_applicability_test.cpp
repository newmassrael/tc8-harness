// A case's applicability to the DUT's configuration (sce_integration/case_applicability.h):
// the trait detection that carries it into the registry, and the verdict line the CLI gate
// prints when a case does not apply.

#include <optional>
#include <string>

#include <gtest/gtest.h>

#include "sce_integration/case_applicability.h"
#include "sce_integration/case_registry.h"

namespace {

using ::tc8::TestConfig;
using ::tc8::sce::IDutControl;

struct AlwaysApplies {};

struct AppliesWhenPassive {
    static std::optional<std::string> applicability(const TestConfig &, IDutControl &) {
        return std::string("dut is active");
    }
};

// Wrong shape: a trait with this signature is not the case's declaration, so it must not be
// picked up and called with arguments it does not take.
struct WrongSignature {
    static std::optional<std::string> applicability(const TestConfig &) { return std::nullopt; }
};

TEST(CaseApplicability, ACaseThatDeclaresNoneAlwaysApplies) {
    EXPECT_FALSE(::tc8::sce::has_applicability_v<AlwaysApplies>);
    EXPECT_EQ(::tc8::sce::applicabilityOf<AlwaysApplies>(), nullptr);
}

TEST(CaseApplicability, ADeclaredFunctionIsCarriedIntoTheEntry) {
    EXPECT_TRUE(::tc8::sce::has_applicability_v<AppliesWhenPassive>);
    EXPECT_NE(::tc8::sce::applicabilityOf<AppliesWhenPassive>(), nullptr);
}

TEST(CaseApplicability, AFunctionOfAnotherShapeIsNotTheDeclaration) {
    EXPECT_FALSE(::tc8::sce::has_applicability_v<WrongSignature>);
    EXPECT_EQ(::tc8::sce::applicabilityOf<WrongSignature>(), nullptr);
}

TEST(CaseApplicability, TheEntryFieldDefaultsToAlwaysApplies) {
    const ::tc8::sce::CaseEntry entry{};
    EXPECT_EQ(entry.applicability, nullptr);
}

TEST(CaseApplicability, TheSkipReasonIsOneToken) {
    using ::tc8::sce::applicabilitySkipReason;
    EXPECT_EQ(applicabilitySkipReason("dut_is_active"), "dut_is_active");
    // A space or a ':' would split the verdict line the orchestrator reads by field.
    EXPECT_EQ(applicabilitySkipReason("DUT is: Active"), "dut_is__active");
    EXPECT_EQ(applicabilitySkipReason(""), "unspecified");
}

TEST(CaseApplicability, TheVerdictNamesAnApplicabilitySkipNotACapabilityOne) {
    EXPECT_EQ(::tc8::sce::applicabilitySkipVerdict("dut is active"),
              "skip:not_applicable_dut_is_active");
}

}  // namespace
