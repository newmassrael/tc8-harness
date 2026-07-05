#include "response_correlation.h"

#include <cstdint>

#include <gtest/gtest.h>

namespace tc8::dut {
namespace {

using Key = ResponseCorrelation::Key;

constexpr Key kA{0x1234, 0x0001, 0x8001};
constexpr Key kB{0x1234, 0x0001, 0x8002};  // same service/instance, different method

constexpr std::uint8_t kMajor      = 0x01;  // the Request's Interface Version
constexpr std::uint8_t kWrongMajor = 0xFF;  // a Response major != the Request's

// --- Session correlation (mode-independent; verified in the stock default) ---

// A Response for a Request the DUT never sent has no correlation — dropped. This
// is the wrong-Session-ID malformation the client ignore property tests.
TEST(ResponseCorrelation, UnrecordedSessionIsRejected) {
    ResponseCorrelation c(/*strict_interface_version=*/false);
    EXPECT_FALSE(c.acceptResponse(kA, 7, kMajor));
}

// The Session ID of a sent Request correlates its Response exactly once; a second
// Response reusing that session finds no pending call (a proxy completed it).
TEST(ResponseCorrelation, RecordedSessionAcceptedOnceThenConsumed) {
    ResponseCorrelation c(false);
    c.recordRequest(kA, 7, kMajor);
    EXPECT_TRUE(c.acceptResponse(kA, 7, kMajor));
    EXPECT_FALSE(c.acceptResponse(kA, 7, kMajor));
}

// A Response whose session differs from the outstanding Request's is rejected; the
// correct session still correlates — the mismatch does not consume the pending one.
TEST(ResponseCorrelation, WrongSessionRejectedCorrectStillAccepted) {
    ResponseCorrelation c(false);
    c.recordRequest(kA, 7, kMajor);
    EXPECT_FALSE(c.acceptResponse(kA, 8, kMajor));
    EXPECT_TRUE(c.acceptResponse(kA, 7, kMajor));
}

// Several Requests to one method each correlate their own Response independently.
TEST(ResponseCorrelation, MultipleOutstandingSessionsEachMatchOnce) {
    ResponseCorrelation c(false);
    c.recordRequest(kA, 7, kMajor);
    c.recordRequest(kA, 9, kMajor);
    EXPECT_TRUE(c.acceptResponse(kA, 9, kMajor));
    EXPECT_TRUE(c.acceptResponse(kA, 7, kMajor));
    EXPECT_FALSE(c.acceptResponse(kA, 7, kMajor));
    EXPECT_FALSE(c.acceptResponse(kA, 9, kMajor));
}

// Correlation is keyed by (service, instance, method): a session recorded for one
// method does not correlate a Response delivered under another.
TEST(ResponseCorrelation, SessionIsIsolatedByKey) {
    ResponseCorrelation c(false);
    c.recordRequest(kA, 7, kMajor);
    EXPECT_FALSE(c.acceptResponse(kB, 7, kMajor));
    EXPECT_TRUE(c.acceptResponse(kA, 7, kMajor));
}

// recordSent() runs the send callable and records the session it returns (paired
// with the Request's major), under the same lock acceptResponse() takes. Here the
// callable stands in for the vsomeip send that stamps and returns the session.
TEST(ResponseCorrelation, RecordSentRunsSendAndRecordsReturnedSession) {
    ResponseCorrelation c(false);
    bool sent = false;
    c.recordSent(kA, kMajor, [&] {
        sent = true;
        return std::uint16_t{7};
    });
    EXPECT_TRUE(sent);
    EXPECT_TRUE(c.acceptResponse(kA, 7, kMajor));
    EXPECT_FALSE(c.acceptResponse(kA, 7, kMajor));
}

// --- Interface-version correlation ---

// Stock default: the major is recorded but NOT enforced — a correctly-sessioned
// Response with a wrong major is still accepted, matching a stock proxy (TD-15's
// original finding).
TEST(ResponseCorrelation, StockModeIgnoresWrongInterfaceVersion) {
    ResponseCorrelation c(/*strict_interface_version=*/false);
    c.recordRequest(kA, 7, kMajor);
    EXPECT_TRUE(c.acceptResponse(kA, 7, kWrongMajor));
}

// Strict mode: a correctly-sessioned Response whose major differs from the
// Request's is rejected — the wrong-Interface-Version malformation — and the
// correlation is CONSUMED, so a later correct-major reply for the same session
// finds no pending call and the request aborts by timeout.
TEST(ResponseCorrelation, StrictWrongInterfaceVersionRejectedAndConsumed) {
    ResponseCorrelation c(/*strict_interface_version=*/true);
    c.recordRequest(kA, 7, kMajor);
    EXPECT_FALSE(c.acceptResponse(kA, 7, kWrongMajor));
    EXPECT_FALSE(c.acceptResponse(kA, 7, kMajor));
}

// Strict mode: a correctly-sessioned, correctly-majored Response is accepted — the
// normal reply, and the error-reaction cases whose Response major matches.
TEST(ResponseCorrelation, StrictCorrectInterfaceVersionAccepted) {
    ResponseCorrelation c(true);
    c.recordRequest(kA, 7, kMajor);
    EXPECT_TRUE(c.acceptResponse(kA, 7, kMajor));
}

// Strict mode still enforces the session first: a wrong session is dropped without
// consuming the pending correlation, exactly as in the stock mode.
TEST(ResponseCorrelation, StrictStillEnforcesSession) {
    ResponseCorrelation c(true);
    c.recordRequest(kA, 7, kMajor);
    EXPECT_FALSE(c.acceptResponse(kA, 8, kMajor));
    EXPECT_TRUE(c.acceptResponse(kA, 7, kMajor));
}

}  // namespace
}  // namespace tc8::dut
