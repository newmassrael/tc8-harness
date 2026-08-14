// The stimulus-axis precondition ledger (tc8/unperformed_stimulus.h).
//
// The behaviour under test is what a verdict reads, so these assert the contract
// the verdict site depends on: that a failed stimulus is visible at all, that the
// reason names WHICH one, and that the answer does not depend on the order in
// which RAII scopes happened to fail.

#include "tc8/unperformed_stimulus.h"

#include <gtest/gtest.h>

#include <string>
#include <thread>
#include <vector>

using tc8::UnperformedStimulus;

namespace {

class UnperformedStimulusTest : public ::testing::Test {
protected:
    void SetUp() override { UnperformedStimulus::reset(); }
    void TearDown() override { UnperformedStimulus::reset(); }
};

TEST_F(UnperformedStimulusTest, CleanRunRecordsNothing) {
    // The common case must stay silent: a run whose stimuli all installed has no
    // record, so nothing downgrades and the DUT is graded normally.
    EXPECT_FALSE(UnperformedStimulus::any());
    EXPECT_TRUE(UnperformedStimulus::reason().empty());
}

TEST_F(UnperformedStimulusTest, ReasonNamesTheStimulus) {
    // An operator reading a report has to be able to tell WHICH stimulus did not
    // happen — "inconclusive" alone would just relocate the mystery.
    UnperformedStimulus::record("tester_inbound_drop");
    EXPECT_TRUE(UnperformedStimulus::any());
    EXPECT_EQ(UnperformedStimulus::reason(),
              "stimulus_tester_inbound_drop_not_performed");
}

TEST_F(UnperformedStimulusTest, FirstRecordWinsSoTheReasonIsDeterministic) {
    // Several scopes can fail in one case (a host with no iptables fails every
    // one of them). The reported reason must not depend on construction or
    // destruction order, or the same broken host yields different reasons run to
    // run and the report stops being comparable.
    UnperformedStimulus::record("tester_inbound_drop");
    UnperformedStimulus::record("tester_auto_rst_drop");
    EXPECT_EQ(UnperformedStimulus::reason(),
              "stimulus_tester_inbound_drop_not_performed");
}

TEST_F(UnperformedStimulusTest, ResetClearsSoARecordCannotLeakForward) {
    // A stale record leaking into the next case would make this guard produce its
    // own false inconclusive — the mirror image of the bug it exists to fix.
    UnperformedStimulus::record("tester_inbound_drop");
    ASSERT_TRUE(UnperformedStimulus::any());
    UnperformedStimulus::reset();
    EXPECT_FALSE(UnperformedStimulus::any());
    EXPECT_TRUE(UnperformedStimulus::reason().empty());
}

TEST_F(UnperformedStimulusTest, ConcurrentRecordsAreSafeAndStillDeterministic) {
    // Scopes are constructed from case code while responder threads run, so the
    // ledger is written under concurrency. Whichever record lands first, exactly
    // one name must survive and it must be one that was actually recorded.
    std::vector<std::thread> threads;
    threads.reserve(8);
    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([i] {
            UnperformedStimulus::record("scope_" + std::to_string(i));
        });
    }
    for (auto &t : threads) t.join();

    ASSERT_TRUE(UnperformedStimulus::any());
    const std::string reason = UnperformedStimulus::reason();
    bool matched_one = false;
    for (int i = 0; i < 8; ++i) {
        if (reason == "stimulus_scope_" + std::to_string(i) + "_not_performed") {
            matched_one = true;
            break;
        }
    }
    EXPECT_TRUE(matched_one) << "reason was not one of the recorded names: " << reason;
}

}  // namespace
