#include "response_correlation.h"

#include <cstdint>

#include <gtest/gtest.h>

namespace tc8::dut {
namespace {

using Key = ResponseCorrelation::Key;

constexpr Key kA{0x1234, 0x0001, 0x8001};
constexpr Key kB{0x1234, 0x0001, 0x8002};  // same service/instance, different method

// A Response for a Request the DUT never sent has no correlation — dropped. This
// is the wrong-Session-ID malformation the client ignore property tests.
TEST(ResponseCorrelation, UnrecordedSessionIsRejected) {
    ResponseCorrelation c;
    EXPECT_FALSE(c.acceptResponse(kA, 7));
}

// The Session ID of a sent Request correlates its Response exactly once; a second
// Response reusing that session finds no pending call (a proxy completed it).
TEST(ResponseCorrelation, RecordedSessionAcceptedOnceThenConsumed) {
    ResponseCorrelation c;
    c.recordRequest(kA, 7);
    EXPECT_TRUE(c.acceptResponse(kA, 7));
    EXPECT_FALSE(c.acceptResponse(kA, 7));
}

// A Response whose session differs from the outstanding Request's is rejected; the
// correct session still correlates — the mismatch does not consume the pending one.
TEST(ResponseCorrelation, WrongSessionRejectedCorrectStillAccepted) {
    ResponseCorrelation c;
    c.recordRequest(kA, 7);
    EXPECT_FALSE(c.acceptResponse(kA, 8));
    EXPECT_TRUE(c.acceptResponse(kA, 7));
}

// Several Requests to one method each correlate their own Response independently.
TEST(ResponseCorrelation, MultipleOutstandingSessionsEachMatchOnce) {
    ResponseCorrelation c;
    c.recordRequest(kA, 7);
    c.recordRequest(kA, 9);
    EXPECT_TRUE(c.acceptResponse(kA, 9));
    EXPECT_TRUE(c.acceptResponse(kA, 7));
    EXPECT_FALSE(c.acceptResponse(kA, 7));
    EXPECT_FALSE(c.acceptResponse(kA, 9));
}

// Correlation is keyed by (service, instance, method): a session recorded for one
// method does not correlate a Response delivered under another.
TEST(ResponseCorrelation, SessionIsIsolatedByKey) {
    ResponseCorrelation c;
    c.recordRequest(kA, 7);
    EXPECT_FALSE(c.acceptResponse(kB, 7));
    EXPECT_TRUE(c.acceptResponse(kA, 7));
}

}  // namespace
}  // namespace tc8::dut
