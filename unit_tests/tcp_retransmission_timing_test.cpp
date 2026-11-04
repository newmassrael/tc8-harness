// The retransmission window policy (tcp_retransmission_timing.h) and the growth
// property TCP_RETRANSMISSION_TO_04 grades (TcpRetransmissionTo04Captured).
#include <chrono>
#include <cstdint>

#include <gtest/gtest.h>

#include "sce_integration/tcp_case_captured.h"
#include "sce_integration/tcp_retransmission_timing.h"

namespace {

using std::chrono::microseconds;
using std::chrono::milliseconds;
using ::tc8::sce::tcp::nextRetransmissionBound;

// The window follows the DUT's own RTO, with a quarter more and one second.
TEST(NextRetransmissionBound, FollowsTheDutsRto) {
    EXPECT_EQ(nextRetransmissionBound(microseconds(400'000), microseconds(0)), milliseconds(1500));
    EXPECT_EQ(nextRetransmissionBound(microseconds(8'000'000), microseconds(0)), milliseconds(11000));
}

// The sender that ended without a verdict under the fixed 8 s window: initial RTO 3 s,
// doubling, so the third retransmission comes 12 s after the second (on a 500 ms tick
// about 10 s). The window for it covers that.
TEST(NextRetransmissionBound, CoversASenderWithTheRfc1122InitialRto) {
    EXPECT_GT(nextRetransmissionBound(microseconds(12'000'000), microseconds(5'000'000)),
              milliseconds(12'000));
}

// Without an RTO the window is three observed intervals, and before any interval the
// RFC 1122 initial RTO.
TEST(NextRetransmissionBound, FallsBackToTheWireThenToTheInitialRto) {
    EXPECT_EQ(nextRetransmissionBound(microseconds(0), microseconds(2'000'000)), milliseconds(8500));
    EXPECT_EQ(nextRetransmissionBound(microseconds(0), microseconds(0)), milliseconds(4750));
}

// RFC 6298 §2.5 lets a sender cap its RTO at any value of at least 60 s; no window
// waits longer than one sized for that.
TEST(NextRetransmissionBound, NeverExceedsTheRfc6298Cap) {
    EXPECT_EQ(nextRetransmissionBound(microseconds(600'000'000), microseconds(0)), milliseconds(76000));
}

::tc8::TcpRetransmissionTo04Captured rtos(std::uint32_t r1, std::uint32_t r2, std::uint32_t r3) {
    ::tc8::TcpRetransmissionTo04Captured c;
    c.ut_tcpi_p1_rto_us = r1;
    c.ut_tcpi_p2_rto_us = r2;
    c.ut_tcpi_p3_rto_us = r3;
    return c;
}

// The pass criterion is growth faster than linear: the steps between RTO values grow.
TEST(TcpRetransmissionTo04Growth, DoublingIsMoreThanLinear) {
    const auto linux_like = rtos(400'000, 800'000, 1'600'000);
    EXPECT_TRUE(linux_like.rto_increasing_2());
    EXPECT_TRUE(linux_like.rto_increasing_3());
    EXPECT_TRUE(linux_like.rto_growth_more_than_linear());
    // An initial RTO of 3 s on a coarse timer (lwIP up to 2.1.x): 6, 12, 24 s.
    EXPECT_TRUE(rtos(6'000'000, 12'000'000, 24'000'000).rto_growth_more_than_linear());
}

// A linear backoff grows on every step and is not "more than linear": the check the
// case used to make (growth alone) passed it.
TEST(TcpRetransmissionTo04Growth, LinearGrowthIsNot) {
    const auto linear = rtos(2'000'000, 3'000'000, 4'000'000);
    EXPECT_TRUE(linear.rto_increasing_2());
    EXPECT_TRUE(linear.rto_increasing_3());
    EXPECT_FALSE(linear.rto_growth_more_than_linear());
}

TEST(TcpRetransmissionTo04Growth, AConstantRtoDoesNotIncrease) {
    const auto constant = rtos(1'000'000, 1'000'000, 1'000'000);
    EXPECT_FALSE(constant.rto_increasing_2());
    EXPECT_FALSE(constant.rto_growth_more_than_linear());
}

// The DUT counting more retransmissions than the capture showed is a capture miss, not
// a DUT that stopped.
TEST(TcpRetransmissionTo04Growth, TheDutsCountTellsACaptureMissFromSilence) {
    ::tc8::TcpRetransmissionTo04Captured c;
    c.retransmissions_seen = 1;
    c.missed_query_valid = true;
    c.missed_retransmits = 2;
    EXPECT_TRUE(c.retransmission_missed_by_capture());
    c.missed_retransmits = 1;
    EXPECT_FALSE(c.retransmission_missed_by_capture());
    c.missed_query_valid = false;
    c.missed_retransmits = 5;
    EXPECT_FALSE(c.retransmission_missed_by_capture());
}

}  // namespace
