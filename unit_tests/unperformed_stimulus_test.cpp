// The stimulus-axis precondition ledger (tc8/unperformed_stimulus.h).
//
// The behaviour under test is what a verdict reads, so these assert the contract
// the verdict site depends on: that a failed stimulus is visible at all, that the
// reason names WHICH one, and that the answer does not depend on the order in
// which RAII scopes happened to fail.

#include "tc8/unperformed_stimulus.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "sce_integration/cases/_tcp_seam.h"

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

// ---- the seam open is a stimulus -------------------------------------------
//
// `seamConnectTcp` is where every TCP case's active OPEN goes, and a failed open
// means the case never asked the DUT the question its guards grade. The header
// claimed that property in prose for a long time while only writing to stderr,
// which no verdict reads — measured 2026-09-25, a phase whose open timed out
// still reported `inconclusive:no_dut_rst_phase2_...`, naming the DUT for a
// window the harness had spent (docs/tech-debt.md TD-24). These two pin the
// behaviour so the claim cannot go back to being only a comment.

// A TCP sub-interface whose OPEN fails, which is the shape a timed-out or refused
// connectTcp RPC has. The sub-interface is PRESENT: `seamConnectTcp` dereferences
// it as a documented contract (the capability gate skips a backend that lacks it
// before stimulus runs), so a fake without one crashes rather than exercising the
// path — which is how the first version of this test was found to prove nothing.
class FailingOpenTcpControl final : public ::tc8::sce::ITcpControl {
public:
    std::optional<::tc8::sce::DutConnection> connectTcp(const ::tc8::sce::Endpoint &,
                                                        const ::tc8::sce::BindSpec &) override {
        return std::nullopt;
    }
    std::optional<::tc8::sce::DutConnection> acceptTcp(const ::tc8::sce::BindSpec &,
                                                       const std::function<void()> &) override {
        return std::nullopt;
    }
    std::optional<::tc8::sce::DutSocket> listenTcp(const ::tc8::sce::BindSpec &) override {
        return std::nullopt;
    }
    bool sendTcp(::tc8::sce::DutSocket, const std::vector<std::uint8_t> &) override { return false; }
    bool sendTcpPattern(::tc8::sce::DutSocket, std::uint8_t, std::uint16_t) override {
        return false;
    }
    std::optional<std::vector<std::uint8_t>> receiveTcp(::tc8::sce::DutSocket, std::uint16_t,
                                                        const std::function<void()> &) override {
        return std::nullopt;
    }
    bool shutdownTcpWr(::tc8::sce::DutSocket) override { return false; }
    bool closeTcp(::tc8::sce::DutSocket) override { return false; }
    bool abortTcp(::tc8::sce::DutSocket) override { return false; }
};

class FailingOpenDutControl final : public ::tc8::sce::IDutControl {
public:
    bool probe() override { return true; }
    bool startTest() override { return true; }
    bool endTest() override { return true; }
    const char *backendName() const override { return "unit-test-failing-open"; }
    std::uint16_t controlPort() const override { return 0; }
    ::tc8::sce::DutCapabilities capabilities() const override {
        return ::tc8::sce::kCapTcpControl;
    }
    ::tc8::sce::ITcpControl *tcpControl() override { return &tcp_; }

private:
    FailingOpenTcpControl tcp_;
};

TEST_F(UnperformedStimulusTest, ASeamOpenThatDoesNotHappenIsRecorded) {
    FailingOpenDutControl dut;
    ::tc8::TestConfig cfg{};
    const auto conn = ::tc8::sce::tcp::seamConnectTcp(dut, cfg, /*local_port=*/1u,
                                                      /*remote_port=*/2u, "unit-test open");
    ASSERT_FALSE(conn.has_value());
    EXPECT_TRUE(UnperformedStimulus::any())
        << "a failed seam open left no record, so the verdict will name the DUT "
           "for a question it was never asked";
    EXPECT_EQ(UnperformedStimulus::reason(), "stimulus_tcp_seam_open_not_performed");
}

TEST_F(UnperformedStimulusTest, TheSeamOpenRecordNamesTheOpenNotTheCase) {
    // One name for every case that opens through the seam, on purpose: the reader
    // needs to know WHICH stimulus did not happen, and "the TCP seam open" is that
    // fact. Per-case names would multiply the vocabulary without adding anything a
    // report consumer can act on.
    FailingOpenDutControl dut;
    ::tc8::TestConfig cfg{};
    (void)::tc8::sce::tcp::seamConnectTcp(dut, cfg, 1u, 2u, "first");
    (void)::tc8::sce::tcp::seamConnectTcp(dut, cfg, 3u, 4u, "second");
    EXPECT_EQ(UnperformedStimulus::reason(), "stimulus_tcp_seam_open_not_performed");
}

}  // namespace
