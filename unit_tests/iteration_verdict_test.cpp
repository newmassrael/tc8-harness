#include <vector>

#include <gtest/gtest.h>

#include "sce_integration/iteration_verdict.h"

// The verdict of a case made of iterations is the conjunction of theirs: it passes only
// when every iteration did, and the worst one decides and is named.

namespace tc8::sce {
namespace {

constexpr int kErr = 3;

ConjoinedVerdict conjoin(std::vector<IterationOutcome> o, std::size_t expected) {
    return conjoinIterations(o, expected, kErr);
}

TEST(IterationVerdict, AllPassIsPass) {
    const auto v = conjoin({{"pass", 0}, {"pass", 0}, {"pass", 0}}, 3);
    EXPECT_EQ(v.verdict, "pass");
    EXPECT_EQ(v.exit_code, 0);
    EXPECT_EQ(v.deciding, -1);
}

TEST(IterationVerdict, AFailInALaterIterationFailsTheCaseAndNamesIt) {
    const auto v = conjoin({{"pass", 0}, {"fail:no_dut_rst", 1}, {"pass", 0}}, 3);
    EXPECT_EQ(v.verdict, "fail:iteration_2_no_dut_rst");
    EXPECT_EQ(v.exit_code, 1);
    EXPECT_EQ(v.deciding, 1);
}

// A fail in one iteration is never hidden by what another found.
TEST(IterationVerdict, AFailOutranksAnInconclusiveAndAnErrorEvenWhenEarlier) {
    EXPECT_EQ(conjoin({{"inconclusive:x", 4}, {"fail:y", 1}}, 2).verdict, "fail:iteration_2_y");
    EXPECT_EQ(conjoin({{"error:e", 3}, {"fail:y", 1}}, 2).verdict, "fail:iteration_2_y");
}

TEST(IterationVerdict, SeverityIsFailThenErrorThenInconclusiveThenSkip) {
    EXPECT_EQ(conjoin({{"skip:s", 2}, {"inconclusive:i", 4}}, 2).verdict, "inconclusive:iteration_2_i");
    EXPECT_EQ(conjoin({{"inconclusive:i", 4}, {"error:e", 3}}, 2).verdict, "error:iteration_2_e");
    EXPECT_EQ(conjoin({{"pass", 0}, {"skip:s", 2}}, 2).verdict, "skip:iteration_2_s");
}

TEST(IterationVerdict, TheFirstOfEquallyBadIterationsDecides) {
    const auto v = conjoin({{"fail:a", 1}, {"fail:b", 1}}, 2);
    EXPECT_EQ(v.verdict, "fail:iteration_1_a");
    EXPECT_EQ(v.deciding, 0);
}

TEST(IterationVerdict, ANoVerdictLineIsAFail) {
    const auto v = conjoin({{"pass", 0}, {"", 1}}, 2);
    EXPECT_EQ(v.verdict, "fail:iteration_2_did_not_return_pass_verdict");
}

TEST(IterationVerdict, AnUnreadableClassIsNotAPass) {
    EXPECT_EQ(conjoin({{"banana", 0}}, 1).verdict, "banana:iteration_1");
    EXPECT_NE(conjoin({{"banana", 0}}, 1).verdict, "pass");
}

TEST(IterationVerdict, ARunStoppedBeforeEveryIterationRanConcludesNothing) {
    const auto v = conjoin({{"pass", 0}}, 3);
    EXPECT_EQ(v.verdict, "error:interrupted_before_all_iterations_ran");
    EXPECT_EQ(v.exit_code, kErr);
    // ... unless an iteration that did run already failed the case.
    EXPECT_EQ(conjoin({{"fail:z", 1}}, 3).verdict, "fail:iteration_1_z");
}

TEST(IterationVerdict, AReasonlessVerdictStillNamesTheIteration) {
    EXPECT_EQ(conjoin({{"fail", 1}}, 1).verdict, "fail:iteration_1");
}

}  // namespace
}  // namespace tc8::sce
