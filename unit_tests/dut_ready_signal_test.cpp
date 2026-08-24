// The launcher-to-harness `--go-file` contract (tc8/dut_ready_signal.h).
//
// The reader is the half that decides whether a case is allowed to conclude about
// the DUT, so these assert the three states directly. Before this header existed
// the reading lived inside the CLI command and only the WRITER's side (the
// orchestrator's Rust tests) was pinned — a reader that quietly started treating
// mere existence as "bound" would have left those green while removing the guard.

#include "tc8/dut_ready_signal.h"

#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>
#include <string>

using tc8::DutReadyState;
using tc8::readDutReadySignal;

namespace {

class DutReadySignalTest : public ::testing::Test {
protected:
    void SetUp() override {
        path_ = std::string(::testing::TempDir()) + "dut_ready_signal_test.go";
        std::remove(path_.c_str());
    }
    void TearDown() override { std::remove(path_.c_str()); }

    void write(const std::string &body) {
        std::ofstream f(path_, std::ios::binary | std::ios::trunc);
        f << body;
    }

    std::string path_;
};

TEST_F(DutReadySignalTest, AbsentIsUndecidedNotBound) {
    // The state the reader spends almost all its time in. It must never be read as
    // an answer about the DUT: the launcher has simply not finished deciding, and
    // treating it as "bound" would remove the barrier entirely.
    const auto r = readDutReadySignal(path_);
    EXPECT_EQ(r.state, DutReadyState::Undecided);
    EXPECT_TRUE(r.reason.empty());
}

TEST_F(DutReadySignalTest, EmptyMeansTheDutIsBound) {
    // The happy path, and the ONLY thing that clears a case to conclude.
    write("");
    EXPECT_EQ(readDutReadySignal(path_).state, DutReadyState::Bound);
}

TEST_F(DutReadySignalTest, NonEmptyMeansNotBoundAndCarriesTheReason) {
    // An operator reading the case log has to learn WHY without also having to find
    // the launcher's log — that is the whole point of putting the reason in the file
    // rather than signalling by absence.
    write("the DUT exited before announcing readiness (see /x/y.dut.log)\n");
    const auto r = readDutReadySignal(path_);
    EXPECT_EQ(r.state, DutReadyState::NotBound);
    EXPECT_EQ(r.reason, "the DUT exited before announcing readiness (see /x/y.dut.log)");
}

TEST_F(DutReadySignalTest, TrailingNewlinesDoNotMakeAReasonLookEmpty) {
    // The writer terminates its line. If the trim were applied to the whole body
    // instead of just the terminator — or omitted so a bare "\n" compared non-empty
    // — the two states would swap, which fails in the direction that matters:
    // a reason mistaken for "bound" silently clears a case that cannot conclude.
    write("no route to the DUT\r\n\n");
    const auto r = readDutReadySignal(path_);
    EXPECT_EQ(r.state, DutReadyState::NotBound);
    EXPECT_EQ(r.reason, "no route to the DUT");

    // ...and a file holding ONLY a terminator is still the "bound" signal, since
    // the launcher wrote no reason.
    write("\n");
    EXPECT_EQ(readDutReadySignal(path_).state, DutReadyState::Bound);
}

TEST_F(DutReadySignalTest, AnOverlongReasonStillReadsNotBound) {
    // The read is capped. Truncation must not be able to flip the verdict: any
    // non-empty prefix is still a refusal to clear the case.
    write(std::string(4096, 'x'));
    const auto r = readDutReadySignal(path_);
    EXPECT_EQ(r.state, DutReadyState::NotBound);
    EXPECT_FALSE(r.reason.empty());
    EXPECT_LE(r.reason.size(), 511U);
}

}  // namespace
