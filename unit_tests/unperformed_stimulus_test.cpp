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
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/recording_dut_control.h"
#include "stimulus/reliable_method_session.h"
#include "stimulus/tx_observer.h"
#include "stimulus/udp_emit.h"

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
    std::optional<::tc8::sce::DutSocket> createTcp(const ::tc8::sce::BindSpec &) override {
        return std::nullopt;
    }
    bool sendTcp(::tc8::sce::DutSocket, const std::vector<std::uint8_t> &) override { return false; }
    bool sendTcpPattern(::tc8::sce::DutSocket, std::uint8_t, std::uint16_t) override {
        return false;
    }
    bool sendTcpWithFlags(::tc8::sce::DutSocket, const std::vector<std::uint8_t> &,
                          ::tc8::sce::TcpSendFlags) override {
        return false;
    }
    // Answered, with nothing received.
    ::tc8::sce::DutReceiveOutcome receiveTcp(::tc8::sce::DutSocket, std::uint16_t,
                                             const std::function<void()> &) override {
        return ::tc8::sce::DutReceiveOutcome::received({});
    }
    bool shutdownTcpWr(::tc8::sce::DutSocket) override { return false; }
    // Refused for "connection does not exist", the answer RFC 793 3.9 requires on a
    // closed connection.
    ::tc8::sce::DutCallOutcome closeTcp(::tc8::sce::DutSocket) override { return refusal(); }
    ::tc8::sce::DutCallOutcome abortTcp(::tc8::sce::DutSocket) override { return refusal(); }

private:
    static ::tc8::sce::DutCallOutcome refusal() {
        return ::tc8::sce::DutCallOutcome::refused(
            ::tc8::sce::DutCallOutcome::Refusal::kConnectionDoesNotExist);
    }
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

// The DUT-control decorator every backend is built inside (makeDutControl).
TEST_F(UnperformedStimulusTest, ADutControlActionTheDutDidNotPerformIsRecorded) {
    // abortTcp's result is what TCP_CALL_ABORT_03 discarded in all three phases: a
    // refused abort followed by "the DUT sent no RST" graded the tester's request.
    ::tc8::sce::RecordingDutControl dut(std::make_unique<FailingOpenDutControl>());
    EXPECT_FALSE(dut.tcpControl()->abortTcp(::tc8::sce::DutSocket{1}).isDone());
    EXPECT_EQ(UnperformedStimulus::reason(), "stimulus_dut_control_abort_tcp_not_performed");
}

TEST_F(UnperformedStimulusTest, ARefusalTheCaseGradesIsTheDutsAnswer) {
    // RFC 793 3.9 CLOSE / ABORT on a closed connection: the refusal is the verdict's
    // input, so it must not turn the run inconclusive.
    ::tc8::sce::RecordingDutControl dut(std::make_unique<FailingOpenDutControl>());
    const ::tc8::sce::DutCallIntentScope graded(::tc8::sce::DutCallIntent::kGraded);
    const auto outcome = dut.tcpControl()->closeTcp(::tc8::sce::DutSocket{1});
    EXPECT_EQ(outcome.refusal, ::tc8::sce::DutCallOutcome::Refusal::kConnectionDoesNotExist);
    EXPECT_FALSE(UnperformedStimulus::any());
}

TEST_F(UnperformedStimulusTest, ACleanupCallBearsOnNoVerdict) {
    ::tc8::sce::RecordingDutControl dut(std::make_unique<FailingOpenDutControl>());
    {
        const ::tc8::sce::DutCallIntentScope cleanup(::tc8::sce::DutCallIntent::kCleanup);
        (void)dut.tcpControl()->closeTcp(::tc8::sce::DutSocket{1});
    }
    EXPECT_FALSE(UnperformedStimulus::any());
    // The scope ended: the next call is a stimulus again.
    (void)dut.tcpControl()->closeTcp(::tc8::sce::DutSocket{1});
    EXPECT_TRUE(UnperformedStimulus::any());
}

TEST_F(UnperformedStimulusTest, ADutControlQueryAnswerIsAnObservationNotAFailure) {
    // "Nothing arrived" and "no peer connected" are what the DUT did.
    ::tc8::sce::RecordingDutControl dut(std::make_unique<FailingOpenDutControl>());
    EXPECT_TRUE(dut.tcpControl()->receiveTcp(::tc8::sce::DutSocket{1}, 16, {}).returned({}));
    EXPECT_FALSE(dut.tcpControl()->acceptTcp(::tc8::sce::BindSpec{}, {}).has_value());
    EXPECT_FALSE(UnperformedStimulus::any());
}

TEST_F(UnperformedStimulusTest, AReceiveThatGotNoAnswerIsRecorded) {
    // The question never came back, which says nothing about the DUT.
    // An opcode backend pointed at a loopback port nothing serves: every request
    // times out unanswered.
    struct Unanswered final : ::tc8::sce::IDutControl {
        bool probe() override { return true; }
        bool startTest() override { return true; }
        bool endTest() override { return true; }
        const char *backendName() const override { return "unit-test-unanswered"; }
        std::uint16_t controlPort() const override { return 0; }
        ::tc8::sce::DutCapabilities capabilities() const override {
            return ::tc8::sce::kCapTcpControl;
        }
        ::tc8::sce::ITcpControl *tcpControl() override { return &tcp; }
        ::tc8::sce::OpcodeTcpControl tcp{0x0100007FU, /*port=*/1, 0, /*timeout_ms=*/100};
    };
    ::tc8::sce::RecordingDutControl dut(std::make_unique<Unanswered>());
    EXPECT_FALSE(dut.tcpControl()->receiveTcp(::tc8::sce::DutSocket{1}, 16, {}).answered());
    EXPECT_EQ(UnperformedStimulus::reason(), "stimulus_dut_control_receive_tcp_not_performed");
}

TEST_F(UnperformedStimulusTest, TheDecoratorIsAbsentWhereTheBackendHasNoInterface) {
    // The capability gate must see the backend unchanged.
    ::tc8::sce::RecordingDutControl dut(std::make_unique<FailingOpenDutControl>());
    EXPECT_NE(dut.tcpControl(), nullptr);
    EXPECT_EQ(dut.udpControl(), nullptr);
    EXPECT_EQ(dut.arpControl(), nullptr);
    EXPECT_EQ(dut.capabilities(), ::tc8::sce::kCapTcpControl);
}

// An interface name no host carries, so a send from it fails without any privilege.
constexpr const char *kNoSuchInterface = "tc8-no-such-if";

TEST_F(UnperformedStimulusTest, AFailedSendIsRecordedByThePrimitiveNotTheCase) {
    // Most cases ignore an emitter's negative return. A verdict on the DUT's
    // silence after such a send would grade the tester's failure as the DUT's, so
    // the primitive records it itself (stimulus/tx_observer.h, reportTxFailed).
    const int rc = ::tc8::stimulus::sendUdpUnicast({0x00}, kNoSuchInterface, 0, 0x0100007FU, 9);
    ASSERT_LT(rc, 0);
    EXPECT_TRUE(UnperformedStimulus::any())
        << "a send that never left the tester left no record";
    // Called with no emitter around it, the primitive is its own outermost scope.
    EXPECT_EQ(UnperformedStimulus::reason(), "stimulus_tx_sendUdpUnicast_not_performed");
}

TEST_F(UnperformedStimulusTest, TheRecordNamesTheEmitterTheCaseCalled) {
    // The emitter is what a reader of the report can find in the case; the
    // primitive underneath it is the same for dozens of emitters.
    {
        ::tc8::stimulus::TxScope scope("emitUnitTestProbe");
        (void)::tc8::stimulus::sendUdpUnicast({0x00}, kNoSuchInterface, 0, 0x0100007FU, 9);
    }
    EXPECT_EQ(UnperformedStimulus::reason(), "stimulus_tx_emitUnitTestProbe_not_performed");
}

TEST_F(UnperformedStimulusTest, AHeldReliableConnectionThatCannotOpenIsRecorded) {
    // The connection a reliable Response must come back on: without it, the
    // Response's absence is the tester's doing.
    const ::tc8::stimulus::ReliableMethodSession session(kNoSuchInterface,
                                                         ::tc8::stimulus::Endpoint{0x0100007FU, 9});
    EXPECT_FALSE(session.valid());
    EXPECT_EQ(UnperformedStimulus::reason(), "stimulus_tx_connectTcpFromIface_not_performed");
}

TEST_F(UnperformedStimulusTest, ASendThatWorksRecordsNothing) {
    // The other half of the contract: a primitive that did its job must not
    // downgrade the run. Loopback always has an IPv4 address.
    const int rc = ::tc8::stimulus::sendUdpUnicast({0x00}, "lo", 0, 0x0100007FU, 9);
    ASSERT_EQ(rc, 0);
    EXPECT_FALSE(UnperformedStimulus::any());
}

}  // namespace
